#pragma once

#include "logger.h"
#include "decoder.h"

#include <vector>
#include <unordered_map>
#include <set>
#include <optional>
#include <utility>
#include <functional>

using Fingerprint = std::pair<size_t, size_t>;

struct FingerprintHash {
  std::size_t operator()(const Fingerprint &fp) const {
    auto hash1 = std::hash<size_t>{}(fp.first);
    auto hash2 = std::hash<size_t>{}(fp.second);
    return hash1 ^ (hash2 + 0x9e3779b9 + (hash1 << 6) + (hash1 >> 2));
  }
};

class FunctionAnalyzer {
public:
  struct BasicBlock {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<uint64_t> successors;
    std::vector<std::string> instructions;
  };

  struct Function {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<BasicBlock> basic_blocks;
    Fingerprint fingerprint;
    double similarity_score{0.0};
    std::vector<std::string> diff_details;
  };

  FunctionAnalyzer(const uint8_t* data, size_t size, uint64_t base_address);

  auto IdentifyFunctions() -> std::vector<Function>;
  auto AnalyzeFunction(uint64_t start_address) -> Function;
  
  static auto LevenshteinDistance(
      const std::vector<std::string>& seq1,
      const std::vector<std::string>& seq2) -> size_t;

private:
  auto FindBasicBlocks(uint64_t start_address) -> std::vector<BasicBlock>;
  auto IsJumpInstruction(const ZydisDecodedInstruction& instruction) const -> bool;
  auto IsCallInstruction(const ZydisDecodedInstruction& instruction) const -> bool;
  auto IsReturnInstruction(const ZydisDecodedInstruction& instruction) const -> bool;
  auto IsControlFlowInstruction(const ZydisDecodedInstruction& instruction) const -> bool;
  auto GetJumpTarget(const ZydisDecodedInstruction& instruction, 
                    const ZydisDecodedOperand* operands,
                    uint64_t current_address) const -> std::optional<uint64_t>;

  static auto CalculateInstructionSimilarity(
      const std::string& instr1, 
      const std::string& instr2) -> double;
      

  const uint8_t* data_;
  size_t size_;
  uint64_t base_address_;
  Zydis decoder_;
  std::set<uint64_t> function_starts_;
}; 
