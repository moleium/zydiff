#include "analyzer.h"
#include <algorithm>
#include <stack>

subroutine_analyzer::subroutine_analyzer(const uint8_t* data, size_t size, uint64_t base_address) :
    data_(data), size_(size), base_address_(base_address) {
}

std::vector<subroutine_analyzer::subroutine> subroutine_analyzer::get_subroutines() {
  std::vector<subroutine> functions;
  LOG("Scanning for functions in %zu bytes of data\n", size_);

  for (size_t offset = 0; offset < size_ - 15; offset++) {
    // already marked as a function start
    if (function_starts_.contains(base_address_ + offset)) {
      continue;
    }

    if (!decoder_.disassemble(base_address_ + offset, data_ + offset, size_ - offset)) {
      continue;
    }

    auto instr = decoder_.get_decoded_instruction();
    auto operands = decoder_.get_decoded_operands();

    // push rbp
    if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].reg.value == ZYDIS_REGISTER_RBP) {

      // mov rbp, rsp
      size_t next_offset = offset + instr.length;
      if (next_offset < size_ - 3 &&
          decoder_.disassemble(base_address_ + next_offset, data_ + next_offset, size_ - next_offset)) {
        auto next_instr = decoder_.get_decoded_instruction();
        auto next_ops = decoder_.get_decoded_operands();

        if (next_instr.mnemonic == ZYDIS_MNEMONIC_MOV && next_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            next_ops[0].reg.value == ZYDIS_REGISTER_RBP && next_ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            next_ops[1].reg.value == ZYDIS_REGISTER_RSP) {
          function_starts_.insert(base_address_ + offset);
          continue;
        }
      }
    }

    // sub rsp, XX
    if (instr.mnemonic == ZYDIS_MNEMONIC_SUB && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].reg.value == ZYDIS_REGISTER_RSP && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      function_starts_.insert(base_address_ + offset);
      continue;
    }

    // push registers sequence
    if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
      size_t push_count = 0;
      size_t curr_offset = offset;

      while (curr_offset < size_ - 3 && push_count < 4) {
        if (!decoder_.disassemble(base_address_ + curr_offset, data_ + curr_offset, size_ - curr_offset)) {
          break;
        }

        auto curr_instr = decoder_.get_decoded_instruction();
        if (curr_instr.mnemonic != ZYDIS_MNEMONIC_PUSH) {
          break;
        }

        push_count++;
        curr_offset += curr_instr.length;
      }

      if (push_count >= 2) {
        function_starts_.insert(base_address_ + offset);
        continue;
      }
    }
  }

  LOG("Found %zu function starts\n", function_starts_.size());

  for (auto start_address : function_starts_) {
    functions.push_back(analyze_subroutines(start_address));
  }

  return functions;
}

auto subroutine_analyzer::analyze_subroutines(uint64_t start_address) -> subroutine_analyzer::subroutine {
  subroutine function;
  function.start_address = start_address;
  function.basic_blocks = find_basic_blocks(start_address);

  size_t total_instructions = 0;
  for (const auto& block : function.basic_blocks) {
    total_instructions += block.instructions.size();
  }
  function.fingerprint = {function.basic_blocks.size(), total_instructions};

  // Find the highest address in any basic block for the function end
  function.end_address = start_address;
  for (const auto& block : function.basic_blocks) {
    function.end_address = std::max(function.end_address, block.end_address);
  }

  return function;
}

auto subroutine_analyzer::find_basic_blocks(uint64_t start_address) -> std::vector<subroutine_analyzer::basic_block> {
  std::vector<basic_block> blocks;
  std::set<uint64_t> processed_addresses;

  std::stack<uint64_t> address_stack;
  address_stack.push(start_address);

  while (!address_stack.empty()) {
    auto current_address = address_stack.top();
    address_stack.pop();

    if (processed_addresses.contains(current_address)) {
      continue;
    }

    basic_block block;
    block.start_address = current_address;

    auto offset = current_address - base_address_;

    while (offset < size_) {
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
          if (next_address < base_address_ + size_) {
            block.successors.push_back(next_address);
            address_stack.push(next_address);
          }
          break;
        }

        if (auto target = get_jump_target(decoded_instruction, decoded_operands, current_address)) {
          if (*target >= base_address_ && *target < base_address_ + size_) {
            block.successors.push_back(*target);
            address_stack.push(*target);
          }
        }

        // if its not an unconditional jmp
        // it also has a fall through path to the next instruction
        if (decoded_instruction.mnemonic != ZYDIS_MNEMONIC_JMP) {
          auto next_address = current_address + decoded_instruction.length;
          if (next_address < base_address_ + size_) {
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

auto subroutine_analyzer::is_jmp(const ZydisDecodedInstruction& instruction) const -> bool {
  return ZYDIS_MNEMONIC_JB <= instruction.mnemonic && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

auto subroutine_analyzer::is_call(const ZydisDecodedInstruction& instruction) const -> bool {
  return instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
}

auto subroutine_analyzer::is_return(const ZydisDecodedInstruction& instruction) const -> bool {
  return instruction.mnemonic == ZYDIS_MNEMONIC_RET;
}

auto subroutine_analyzer::is_control_flow(const ZydisDecodedInstruction& instruction) -> bool {
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

auto subroutine_analyzer::get_jump_target(
  const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operands, uint64_t current_address
) const -> std::optional<uint64_t> {

  if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
    if (operands[0].imm.is_relative) {
      // relative jump, calculate absolute target
      return current_address + instruction.length + operands[0].imm.value.s;
    } else {
      // absolute jump, use the immediate value directly
      return operands[0].imm.value.u;
    }
  }

  return std::nullopt;
}

/*
 * measure the difference between two sequences by
 * calculating the minimum number of single character edits
 * (insertions, deletions, or substitutions)
 * required to change one word into the other.
 */
auto subroutine_analyzer::levenshtein_distance(
  const std::vector<std::string>& seq1, const std::vector<std::string>& seq2
) -> std::size_t {
  const size_t m = seq1.size();
  const size_t n = seq2.size();

  std::vector<std::vector<size_t>> dp(m + 1, std::vector<size_t>(n + 1));

  for (size_t i = 0; i <= m; i++)
    dp[i][0] = i;
  for (size_t j = 0; j <= n; j++)
    dp[0][j] = j;

  for (size_t i = 1; i <= m; i++) {
    for (size_t j = 1; j <= n; j++) {
      if (seq1[i - 1] == seq2[j - 1])
        dp[i][j] = dp[i - 1][j - 1];
      else
        // clang-format off
        dp[i][j] = 1 + std::min({
          dp[i - 1][j],    // deletion
          dp[i][j - 1],    // insertion
          dp[i - 1][j - 1] // substitution
        });
      // clang-format on
    }
  }

  return dp[m][n];
}
