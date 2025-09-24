#pragma once

#include "decoder.h"
#include "logger.h"

#include <functional>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

using fingerprint = std::pair<size_t, size_t>;

struct fingerprint_hash {
  std::size_t operator()(const fingerprint& fp) const {
    auto hash1 = std::hash<size_t>{}(fp.first);
    auto hash2 = std::hash<size_t>{}(fp.second);
    return hash1 ^ (hash2 + 0x9e3779b9 + (hash1 << 6) + (hash1 >> 2));
  }
};

class subroutine_analyzer {
  public:
  struct basic_block {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<uint64_t> successors;
    std::vector<std::string> instructions;
  };

  struct subroutine {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<basic_block> basic_blocks;
    fingerprint fingerprint;
    double similarity_score{0.0};
    std::vector<std::string> diff_details;
  };

  subroutine_analyzer(const uint8_t* data, size_t size, uint64_t base_address);

  std::vector<subroutine> get_subroutines();

  static std::size_t levenshtein_distance(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2);

  private:
  std::vector<basic_block> find_basic_blocks(uint64_t start_address);
  subroutine analyze_subroutine(uint64_t start_address);

  bool is_jmp(const ZydisDecodedInstruction& instruction) const;
  bool is_call(const ZydisDecodedInstruction& instruction) const;
  bool is_return(const ZydisDecodedInstruction& instruction) const;
  bool is_control_flow(const ZydisDecodedInstruction& instruction);
  std::optional<uint64_t> get_jump_target(
          const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operands, uint64_t current_address
  ) const;

  static double get_similarity_score(const std::string& first, const std::string& second);


  const uint8_t* data_;
  size_t size_;
  uint64_t base_address_;
  zydis decoder_;
};
