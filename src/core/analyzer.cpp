#include "analyzer.h"
#include <stack>

FunctionAnalyzer::FunctionAnalyzer(const uint8_t *data, size_t size,
                                   uint64_t base_address)
    : data_(data), size_(size), base_address_(base_address) {}

auto FunctionAnalyzer::IdentifyFunctions() -> std::vector<Function> {
  std::vector<Function> functions;
  LOG("Scanning for functions in %zu bytes of data\n", size_);

  for (size_t offset = 0; offset < size_ - 15; offset++) {
    // already marked as a function start
    if (function_starts_.contains(base_address_ + offset)) {
      continue;
    }

    if (!decoder_.Disassemble(base_address_ + offset, data_ + offset, size_ - offset)) {
      continue;
    }

    auto instr = decoder_.GetDecodedInstruction();
    auto operands = decoder_.GetDecodedOperands();

    // push rbp
    if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH && 
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].reg.value == ZYDIS_REGISTER_RBP) {
      
      //mov rbp, rsp
      size_t next_offset = offset + instr.length;
      if (next_offset < size_ - 3 && 
          decoder_.Disassemble(base_address_ + next_offset, 
                             data_ + next_offset, size_ - next_offset)) {
        auto next_instr = decoder_.GetDecodedInstruction();
        auto next_ops = decoder_.GetDecodedOperands();
        
        if (next_instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
            next_ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            next_ops[0].reg.value == ZYDIS_REGISTER_RBP &&
            next_ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            next_ops[1].reg.value == ZYDIS_REGISTER_RSP) {
          function_starts_.insert(base_address_ + offset);
          continue;
        }
      }
    }

    // sub rsp, XX
    if (instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].reg.value == ZYDIS_REGISTER_RSP &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      function_starts_.insert(base_address_ + offset);
      continue;
    }

    // push registers sequence
    if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
      bool is_prolog = true;
      size_t push_count = 0;
      size_t curr_offset = offset;
      
      while (curr_offset < size_ - 3 && push_count < 4) {
        if (!decoder_.Disassemble(base_address_ + curr_offset, 
                                data_ + curr_offset, 
                                size_ - curr_offset)) {
          is_prolog = false;
          break;
        }

        auto curr_instr = decoder_.GetDecodedInstruction();
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
    functions.push_back(AnalyzeFunction(start_address));
  }

  return functions;
}

auto FunctionAnalyzer::AnalyzeFunction(uint64_t start_address) -> Function {
  Function function;
  function.start_address = start_address;
  function.basic_blocks = FindBasicBlocks(start_address);

  // Calculate fingerprint
  size_t total_instructions = 0;
  for (const auto& block : function.basic_blocks) {
    total_instructions += block.instructions.size();
  }
  function.fingerprint = {function.basic_blocks.size(), total_instructions};

  // Find the highest address in any basic block for the function end
  function.end_address = start_address;
  for (const auto &block : function.basic_blocks) {
    function.end_address = std::max(function.end_address, block.end_address);
  }

  return function;
}

auto FunctionAnalyzer::FindBasicBlocks(uint64_t start_address)
    -> std::vector<BasicBlock> {
  std::vector<BasicBlock> blocks;
  std::set<uint64_t> block_starts{start_address};
  std::set<uint64_t> processed_addresses;

  std::stack<uint64_t> address_stack;
  address_stack.push(start_address);

  while (!address_stack.empty()) {
    auto current_address = address_stack.top();
    address_stack.pop();

    if (processed_addresses.contains(current_address)) {
      continue;
    }

    BasicBlock block;
    block.start_address = current_address;

    auto offset = current_address - base_address_;

    while (offset < size_) {
      if (!decoder_.Disassemble(current_address, data_ + offset, size_ - offset)) {
        break;
      }

      auto instruction = decoder_.GetInstruction();
      auto decoded_instruction = decoder_.GetDecodedInstruction();
      auto decoded_operands = decoder_.GetDecodedOperands();

      block.instructions.push_back(instruction);

      if (IsControlFlowInstruction(decoded_instruction)) {
        if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
          break;
        }

        if (auto target = GetJumpTarget(decoded_instruction, decoded_operands,
                                        current_address)) {
          block_starts.insert(*target);
          block.successors.push_back(*target);
          address_stack.push(*target);

          // fall through for conditional jumps
          if (decoded_instruction.mnemonic != ZYDIS_MNEMONIC_JMP) {
            auto next_address = current_address + decoded_instruction.length;
            block_starts.insert(next_address);
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

auto FunctionAnalyzer::IsJumpInstruction(
    const ZydisDecodedInstruction &instruction) const -> bool {
  return ZYDIS_MNEMONIC_JB <= instruction.mnemonic &&
         instruction.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

auto FunctionAnalyzer::IsCallInstruction(
    const ZydisDecodedInstruction &instruction) const -> bool {
  return instruction.mnemonic == ZYDIS_MNEMONIC_CALL;
}

auto FunctionAnalyzer::IsReturnInstruction(
    const ZydisDecodedInstruction &instruction) const -> bool {
  return instruction.mnemonic == ZYDIS_MNEMONIC_RET;
}

auto FunctionAnalyzer::IsControlFlowInstruction(
    const ZydisDecodedInstruction& instruction) const -> bool {
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

auto FunctionAnalyzer::GetJumpTarget(
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_address) const -> std::optional<uint64_t> {
  
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
* string metric for measuring the difference between two sequences.
* defined as the minimum number of single-character edits (insertions, deletions, or substitutions)
* required to change one word into the other.
*/
auto FunctionAnalyzer::LevenshteinDistance(
    const std::vector<std::string>& seq1,
    const std::vector<std::string>& seq2) -> size_t {
  const size_t m = seq1.size();
  const size_t n = seq2.size();
  
  std::vector<std::vector<size_t>> dp(
      m + 1, std::vector<size_t>(n + 1));

  for (size_t i = 0; i <= m; i++)
    dp[i][0] = i;
  for (size_t j = 0; j <= n; j++)
    dp[0][j] = j;

  for (size_t i = 1; i <= m; i++) {
    for (size_t j = 1; j <= n; j++) {
      if (seq1[i-1] == seq2[j-1])
        dp[i][j] = dp[i-1][j-1];
      else
        dp[i][j] = 1 + std::min({dp[i-1][j],     // deletion
                                dp[i][j-1],             // insertion
                                dp[i-1][j-1]});         // substitution
    }
  }

  return dp[m][n];
}