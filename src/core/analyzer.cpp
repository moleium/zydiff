#include "analyzer.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <limits>
#include <mutex>
#include <stack>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <unordered_set>

namespace {

  [[nodiscard]] auto normalize_instruction(std::string_view instruction) -> std::string {
    std::string result;
    result.reserve(instruction.size());

    for (size_t i = 0; i < instruction.size(); ++i) {
      if (instruction.substr(i).starts_with("0x")) {
        result += "0x?";
        i += 2;
        while (i < instruction.size() && std::isxdigit(static_cast<unsigned char>(instruction[i]))) {
          ++i;
        }
        --i;
      } else {
        result += instruction[i];
      }
    }
    return result;
  }

  [[nodiscard]] auto calculate_fingerprint(std::span<const subroutine_analyzer::basic_block> blocks) -> fingerprint {
    uint64_t hash = 14695981039346656037ull;
    auto append = [&](std::string_view value) {
      for (const auto ch : value) {
        hash ^= static_cast<uint8_t>(ch);
        hash *= 1099511628211ull;
      }
    };

    for (const auto& block : blocks) {
      hash ^= block.instructions.size();
      hash *= 1099511628211ull;
      hash ^= block.successors.size();
      hash *= 1099511628211ull;
      for (const auto& instruction : block.instructions) {
        append(normalize_instruction(instruction));
      }
    }

    return static_cast<fingerprint>(hash);
  }

  template <typename value_type>
    requires(std::is_integral_v<value_type> && !std::is_same_v<value_type, bool>)
  void hash_value(uint64_t& hash, value_type value) {
    using unsigned_type = std::make_unsigned_t<value_type>;
    auto normalized = static_cast<unsigned_type>(value);
    for (size_t i = 0; i < sizeof(unsigned_type); ++i) {
      hash ^= static_cast<uint8_t>((normalized >> (i * 8)) & 0xff);
      hash *= 1099511628211ull;
    }
  }

  void hash_value(uint64_t& hash, bool value) {
    hash_value(hash, static_cast<uint8_t>(value ? 1 : 0));
  }

  template <typename value_type>
    requires std::is_enum_v<value_type>
  void hash_value(uint64_t& hash, value_type value) {
    hash_value(hash, static_cast<std::underlying_type_t<value_type>>(value));
  }

  [[nodiscard]] auto is_relative_control_flow_mnemonic(ZydisMnemonic mnemonic) -> bool {
    switch (mnemonic) {
      case ZYDIS_MNEMONIC_CALL:
      case ZYDIS_MNEMONIC_JMP:
      case ZYDIS_MNEMONIC_JB:
      case ZYDIS_MNEMONIC_JBE:
      case ZYDIS_MNEMONIC_JCXZ:
      case ZYDIS_MNEMONIC_JECXZ:
      case ZYDIS_MNEMONIC_JKNZD:
      case ZYDIS_MNEMONIC_JKZD:
      case ZYDIS_MNEMONIC_JL:
      case ZYDIS_MNEMONIC_JLE:
      case ZYDIS_MNEMONIC_JNB:
      case ZYDIS_MNEMONIC_JNBE:
      case ZYDIS_MNEMONIC_JNL:
      case ZYDIS_MNEMONIC_JNLE:
      case ZYDIS_MNEMONIC_JNO:
      case ZYDIS_MNEMONIC_JNP:
      case ZYDIS_MNEMONIC_JNS:
      case ZYDIS_MNEMONIC_JNZ:
      case ZYDIS_MNEMONIC_JO:
      case ZYDIS_MNEMONIC_JP:
      case ZYDIS_MNEMONIC_JRCXZ:
      case ZYDIS_MNEMONIC_JS:
      case ZYDIS_MNEMONIC_JZ:
        return true;
      default:
        return false;
    }
  }

} // namespace

subroutine_analyzer::subroutine_analyzer(const uint8_t* data, size_t size, uint64_t base_address) :
    data_(data), size_(size), base_address_(base_address) {
}

subroutine_analyzer::subroutine_analyzer(
  const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
  bool decode_instructions
) : subroutine_analyzer(data, size, base_address, known_starts, decode_instructions, 1) {
}

subroutine_analyzer::subroutine_analyzer(
  const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
  bool decode_instructions, size_t worker_count
) : subroutine_analyzer(data, size, base_address, known_starts, decode_instructions, worker_count, {}) {
}

subroutine_analyzer::subroutine_analyzer(
  const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
  bool decode_instructions, size_t worker_count, std::stop_token stop_token
) :
    data_(data), size_(size), base_address_(base_address), known_starts_(known_starts.begin(), known_starts.end()),
    decode_instructions_(decode_instructions), worker_count_(std::max(size_t{1}, worker_count)),
    stop_token_(stop_token) {
  std::erase_if(known_starts_, [&](uint64_t address) {
    return address < base_address_ || address >= base_address_ + size_;
  });
  std::ranges::sort(known_starts_);
  known_starts_.erase(std::ranges::unique(known_starts_).begin(), known_starts_.end());
}

std::vector<subroutine_analyzer::subroutine> subroutine_analyzer::get_subroutines() {
  check_stop();
  if (!known_starts_.empty()) {
    std::vector<subroutine> functions(known_starts_.size());
    auto analyze = [&](subroutine_analyzer& analyzer, size_t i) {
      const auto end_address_hint =
        i + 1 < known_starts_.size() ? std::optional<uint64_t>(known_starts_[i + 1]) : std::nullopt;
      functions[i] = decode_instructions_
                       ? analyzer.analyze_subroutine(known_starts_[i], end_address_hint)
                       : analyzer.analyze_range(known_starts_[i], end_address_hint.value_or(base_address_ + size_));
    };

    const auto thread_count = std::min(worker_count_, known_starts_.size());
    if (thread_count == 1) {
      for (size_t i = 0; i < known_starts_.size(); ++i) {
        check_stop();
        analyze(*this, i);
      }
    } else {
      std::atomic_size_t next_index{0};
      std::stop_source stop_source;
      std::exception_ptr failure;
      std::mutex failure_mutex;
      std::vector<std::jthread> workers;
      workers.reserve(thread_count);
      for (size_t i = 0; i < thread_count; ++i) {
        workers.emplace_back([&] {
          try {
            subroutine_analyzer analyzer(
              data_, size_, base_address_, std::span<const uint64_t>{}, decode_instructions_, 1, stop_token_
            );
            analyzer.worker_token_ = stop_source.get_token();
            while (!stop_source.stop_requested() && !stop_token_.stop_requested()) {
              const auto index = next_index.fetch_add(1, std::memory_order_relaxed);
              if (index >= known_starts_.size()) {
                break;
              }
              analyze(analyzer, index);
            }
          } catch (...) {
            stop_source.request_stop();
            const std::scoped_lock lock(failure_mutex);
            if (!failure) {
              failure = std::current_exception();
            }
          }
        });
      }
      workers.clear();
      if (failure) {
        std::rethrow_exception(failure);
      }
      check_stop();
    }

    std::erase_if(functions, [](const auto& function) {
      return function.basic_blocks.empty() && function.byte_size == 0;
    });
    return functions;
  }

  auto function_starts = discover_subroutine_starts();
  std::vector<subroutine> functions;
  functions.reserve(function_starts.size());

  for (auto start_address : function_starts) {
    check_stop();
    functions.push_back(analyze_subroutine(start_address, std::nullopt));
  }

  std::sort(functions.begin(), functions.end(), [](const auto& a, const auto& b) {
    return a.start_address < b.start_address;
  });

  std::vector<subroutine> filtered_functions;
  if (!functions.empty()) {
    filtered_functions.push_back(functions[0]);
    for (size_t i = 1; i < functions.size(); ++i) {
      if (functions[i].start_address >= filtered_functions.back().end_address) {
        filtered_functions.push_back(functions[i]);
      }
    }
  }

  return filtered_functions;
}

void subroutine_analyzer::check_stop() const {
  if (stop_token_.stop_requested() || worker_token_.stop_requested()) {
    throw std::runtime_error("analysis cancelled");
  }
}

std::vector<uint64_t> subroutine_analyzer::discover_subroutine_starts() {
  std::unordered_set<uint64_t> function_starts;
  std::vector<uint64_t> work_queue;

  if (size_ > 0) {
    work_queue.push_back(base_address_);
    function_starts.insert(base_address_);
  }

  size_t work_idx = 0;
  while (work_idx < work_queue.size()) {
    check_stop();
    uint64_t current_address = work_queue[work_idx++];
    size_t offset = current_address - base_address_;

    while (offset < size_) {
      check_stop();
      if (!decoder_.disassemble(current_address, data_ + offset, size_ - offset)) {
        offset++;
        current_address++;
        continue;
      }

      auto decoded_instruction = decoder_.get_decoded_instruction();
      if (is_call(decoded_instruction)) {
        auto operands = decoder_.get_decoded_operands();
        if (auto target_opt = get_jump_target(decoded_instruction, operands, current_address)) {
          uint64_t target = *target_opt;
          if (target >= base_address_ && target < (base_address_ + size_)) {
            if (function_starts.find(target) == function_starts.end()) {
              function_starts.insert(target);
              work_queue.push_back(target);
            }
          }
        }
      }

      if (is_return(decoded_instruction) || decoded_instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
        break;
      }

      offset += decoded_instruction.length;
      current_address += decoded_instruction.length;
    }
  }

  if (size_ < 16) {
    std::vector<uint64_t> starts(function_starts.begin(), function_starts.end());
    std::ranges::sort(starts);
    return starts;
  }

  for (size_t offset = 0; offset < size_ - 15; offset++) {
    if (offset % 4096 == 0) {
      check_stop();
    }
    uint64_t current_address = base_address_ + offset;
    if (function_starts.contains(current_address)) {
      continue;
    }

    if (!decoder_.disassemble(current_address, data_ + offset, size_ - offset)) {
      continue;
    }

    auto instr = decoder_.get_decoded_instruction();
    auto operands = decoder_.get_decoded_operands();

    bool found_prologue = false;
    // push rbp; mov rbp, rsp
    if (
      instr.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
      operands[0].reg.value == ZYDIS_REGISTER_RBP
    ) {
      size_t next_offset = offset + instr.length;
      if (
        next_offset < size_ - 3 &&
        decoder_.disassemble(base_address_ + next_offset, data_ + next_offset, size_ - next_offset)
      ) {
        auto next_instr = decoder_.get_decoded_instruction();
        auto next_ops = decoder_.get_decoded_operands();
        if (
          next_instr.mnemonic == ZYDIS_MNEMONIC_MOV && next_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          next_ops[0].reg.value == ZYDIS_REGISTER_RBP && next_ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          next_ops[1].reg.value == ZYDIS_REGISTER_RSP
        ) {
          found_prologue = true;
        }
      }
    } else if (
      instr.mnemonic == ZYDIS_MNEMONIC_SUB && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
      operands[0].reg.value == ZYDIS_REGISTER_RSP && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
    ) {
      found_prologue = true;
    }

    if (found_prologue) {
      function_starts.insert(current_address);
      offset += instr.length;
    }
  }

  std::vector<uint64_t> starts(function_starts.begin(), function_starts.end());
  std::ranges::sort(starts);
  return starts;
}

subroutine_analyzer::subroutine
subroutine_analyzer::analyze_subroutine(uint64_t start_address, std::optional<uint64_t> end_address_hint) {
  subroutine function;
  function.start_address = start_address;
  function.basic_blocks = find_basic_blocks(start_address, end_address_hint);

  std::ranges::sort(function.basic_blocks, [](const auto& lhs, const auto& rhs) {
    return lhs.start_address < rhs.start_address;
  });

  function.fingerprint = calculate_fingerprint(function.basic_blocks);

  function.end_address = start_address;
  for (const auto& block : function.basic_blocks) {
    function.end_address = std::max(function.end_address, block.end_address);
  }
  set_byte_fingerprint(function);
  set_instruction_fingerprint(function);

  return function;
}

subroutine_analyzer::subroutine subroutine_analyzer::analyze_range(uint64_t start_address, uint64_t end_address) {
  subroutine function;
  function.start_address = start_address;
  function.end_address = std::min(end_address, base_address_ + size_);

  if (function.start_address >= function.end_address) {
    return function;
  }

  set_byte_fingerprint(function);
  set_instruction_fingerprint(function);
  function.fingerprint =
    static_cast<fingerprint>(function.instruction_hash != 0 ? function.instruction_hash : function.byte_hash);
  return function;
}

void subroutine_analyzer::set_byte_fingerprint(subroutine& function) {
  if (function.start_address < base_address_ || function.end_address <= function.start_address) {
    return;
  }

  const auto section_end = base_address_ + size_;
  const auto end_address = std::min(function.end_address, section_end);
  if (end_address <= function.start_address) {
    return;
  }

  const auto start_offset = function.start_address - base_address_;
  const auto byte_count = static_cast<size_t>(end_address - function.start_address);
  uint64_t hash = 14695981039346656037ull;
  for (size_t i = 0; i < byte_count; ++i) {
    if (i % 4096 == 0) {
      check_stop();
    }
    hash ^= data_[start_offset + i];
    hash *= 1099511628211ull;
  }

  function.end_address = end_address;
  function.byte_size = byte_count;
  function.byte_hash = hash;
}

void subroutine_analyzer::set_instruction_fingerprint(subroutine& function) {
  if (function.start_address < base_address_ || function.end_address <= function.start_address) {
    return;
  }

  const auto section_end = base_address_ + size_;
  const auto end_address = std::min(function.end_address, section_end);
  if (end_address <= function.start_address) {
    return;
  }

  ZydisDecoder local_decoder;
  ZydisDecoderInit(&local_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

  auto offset = function.start_address - base_address_;
  const auto end_offset = end_address - base_address_;
  uint64_t hash = 14695981039346656037ull;
  size_t instruction_count = 0;

  // hash mnemonic operand kinds registers memory form and length
  while (offset < end_offset) {
    check_stop();
    ZydisDecodedInstruction instruction{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!ZYAN_SUCCESS(
          ZydisDecoderDecodeFull(&local_decoder, data_ + offset, end_offset - offset, &instruction, operands)
        )) {
      hash_value(hash, data_[offset]);
      ++offset;
      continue;
    }

    hash_value(hash, instruction.mnemonic);
    hash_value(hash, instruction.operand_count_visible);
    hash_value(hash, instruction.length);
    const auto normalize_control_flow = is_relative_control_flow_mnemonic(instruction.mnemonic);

    for (uint8_t i = 0; i < instruction.operand_count; ++i) {
      const auto& operand = operands[i];
      if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN) {
        continue;
      }

      hash_value(hash, operand.type);
      hash_value(hash, operand.size);
      switch (operand.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
          hash_value(hash, operand.reg.value);
          break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
          hash_value(hash, operand.mem.type);
          hash_value(hash, operand.mem.base);
          hash_value(hash, operand.mem.index);
          hash_value(hash, operand.mem.scale);
          break;
        case ZYDIS_OPERAND_TYPE_POINTER:
          hash_value(hash, operand.ptr.segment);
          break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
          hash_value(hash, operand.imm.is_signed);
          // hash immediate signedness and relative flag only
          hash_value(hash, operand.imm.is_relative || normalize_control_flow);
          break;
        default:
          break;
      }
    }

    ++instruction_count;
    offset += instruction.length;
  }

  function.instruction_count = instruction_count;
  function.instruction_hash = hash;
}

std::vector<subroutine_analyzer::basic_block>
subroutine_analyzer::find_basic_blocks(uint64_t start_address, std::optional<uint64_t> end_address_hint) {
  std::vector<basic_block> blocks;
  std::unordered_set<uint64_t> processed_addresses;
  const auto section_end = base_address_ + size_;
  const auto function_end = std::min(end_address_hint.value_or(section_end), section_end);

  std::stack<uint64_t> address_stack;
  address_stack.push(start_address);

  while (!address_stack.empty()) {
    check_stop();
    auto current_address = address_stack.top();
    address_stack.pop();

    if (processed_addresses.contains(current_address)) {
      continue;
    }
    if (current_address < base_address_ || current_address >= function_end) {
      continue;
    }

    basic_block block;
    block.start_address = current_address;

    auto offset = current_address - base_address_;

    while (offset < size_ && current_address < function_end) {
      check_stop();
      if (!decoder_.disassemble(current_address, data_ + offset, size_ - offset)) {
        break;
      }

      auto instruction = decoder_.get_instruction();
      auto decoded_instruction = decoder_.get_decoded_instruction();
      auto decoded_operands = decoder_.get_decoded_operands();

      block.instructions.push_back(instruction);

      if (is_control_flow(decoded_instruction)) {
        if (is_return(decoded_instruction)) {
          break;
        }

        // call instr is the end of bb. only successor is within this function
        if (is_call(decoded_instruction)) {
          auto next_address = current_address + decoded_instruction.length;
          if (next_address < function_end) {
            block.successors.push_back(next_address);
            address_stack.push(next_address);
          }
          break;
        }

        if (auto target = get_jump_target(decoded_instruction, decoded_operands, current_address)) {
          if (*target >= base_address_ && *target < function_end) {
            block.successors.push_back(*target);
            address_stack.push(*target);
          }
        }

        // if its not an unconditional jmp
        // it also has a fall through path to the next instruction
        if (decoded_instruction.mnemonic != ZYDIS_MNEMONIC_JMP) {
          auto next_address = current_address + decoded_instruction.length;
          if (next_address < function_end) {
            block.successors.push_back(next_address);
            address_stack.push(next_address);
          }
        }

        break;
      }

      current_address += decoded_instruction.length;
      offset += decoded_instruction.length;
    }

    block.end_address = current_address;
    blocks.push_back(block);
    processed_addresses.insert(block.start_address);
  }

  return blocks;
}

bool subroutine_analyzer::is_jmp(const ZydisDecodedInstruction& instruction) const {
  return ZYDIS_MNEMONIC_JB <= instruction.mnemonic && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

bool subroutine_analyzer::is_call(const ZydisDecodedInstruction& instruction) const {
  return instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
}

bool subroutine_analyzer::is_return(const ZydisDecodedInstruction& instruction) const {
  return instruction.mnemonic == ZYDIS_MNEMONIC_RET;
}

bool subroutine_analyzer::is_control_flow(const ZydisDecodedInstruction& instruction) {
  switch (instruction.mnemonic) {
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_RET:
    case ZYDIS_MNEMONIC_CALL:
      return true;
    default:
      return false;
  }
}

std::optional<uint64_t> subroutine_analyzer::get_jump_target(
  const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operands, uint64_t current_address
) const {

  if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    if (operands[0].imm.is_relative) {
      if (current_address > std::numeric_limits<uint64_t>::max() - instruction.length) {
        return std::nullopt;
      }
      const auto next_address = current_address + instruction.length;
      const auto displacement = operands[0].imm.value.s;
      if (displacement >= 0) {
        const auto offset = static_cast<uint64_t>(displacement);
        if (next_address > std::numeric_limits<uint64_t>::max() - offset) {
          return std::nullopt;
        }
        return next_address + offset;
      }

      const auto offset = static_cast<uint64_t>(-(displacement + 1)) + 1;
      if (next_address < offset) {
        return std::nullopt;
      }
      return next_address - offset;
    } else {
      return operands[0].imm.value.u;
    }
  }

  return std::nullopt;
}

std::size_t
subroutine_analyzer::levenshtein_distance(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2) {
  const size_t m = seq1.size();
  const size_t n = seq2.size();

  constexpr size_t insert_delete_cost = 100;
  constexpr size_t mismatch_cost = 100;
  constexpr size_t normalized_match_cost = 10;

  if (seq1 == seq2) {
    return 0;
  }

  std::vector<std::string> normalized_first;
  normalized_first.reserve(m);
  for (const auto& instruction : seq1) {
    normalized_first.push_back(normalize_instruction(instruction));
  }

  std::vector<std::string> normalized_second;
  normalized_second.reserve(n);
  for (const auto& instruction : seq2) {
    normalized_second.push_back(normalize_instruction(instruction));
  }

  std::vector<size_t> previous(n + 1);
  std::vector<size_t> current(n + 1);

  for (size_t j = 0; j <= n; ++j) {
    previous[j] = j * insert_delete_cost;
  }

  for (size_t i = 1; i <= m; ++i) {
    current[0] = i * insert_delete_cost;
    for (size_t j = 1; j <= n; ++j) {
      size_t substitution_cost;
      if (seq1[i - 1] == seq2[j - 1]) {
        substitution_cost = 0;
      } else if (normalized_first[i - 1] == normalized_second[j - 1]) {
        substitution_cost = normalized_match_cost;
      } else {
        substitution_cost = mismatch_cost;
      }

      current[j] = std::min({
        previous[j] + insert_delete_cost,
        current[j - 1] + insert_delete_cost,
        previous[j - 1] + substitution_cost,
      });
    }
    std::swap(previous, current);
  }

  return previous[n];
}
