#pragma once

#include "decoder.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

using fingerprint = size_t;

class subroutine_analyzer {
  public:
  struct address_range {
    uint64_t start;
    uint64_t end;
  };

  struct basic_block {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<int64_t> successor_keys;
    std::vector<std::string> instructions;
    std::vector<uint64_t> instruction_keys;
    std::vector<uint64_t> match_keys;
    uint64_t match_hash{14695981039346656037ull};
  };

  struct subroutine {
    uint64_t start_address;
    uint64_t end_address;
    std::vector<basic_block> basic_blocks;
    fingerprint fingerprint;
    size_t byte_size{0};
    size_t instruction_count{0};
    uint64_t instruction_hash{0};
  };

  subroutine_analyzer(const uint8_t* data, size_t size, uint64_t base_address);
  subroutine_analyzer(
    const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
    bool decode_instructions = true
  );
  subroutine_analyzer(
    const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
    bool decode_instructions, size_t worker_count
  );
  subroutine_analyzer(
    const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
    bool decode_instructions, size_t worker_count, std::stop_token stop_token
  );
  subroutine_analyzer(
    const uint8_t* data, size_t size, uint64_t base_address, std::span<const uint64_t> known_starts,
    bool decode_instructions, size_t worker_count, std::stop_token stop_token,
    std::span<const address_range> address_ranges
  );

  std::vector<subroutine> get_subroutines();

  static std::size_t levenshtein_distance(const std::vector<uint64_t>& seq1, const std::vector<uint64_t>& seq2);

  private:
  std::vector<basic_block> find_basic_blocks(uint64_t start_address, std::optional<uint64_t> end_address_hint);
  subroutine analyze_subroutine(uint64_t start_address, std::optional<uint64_t> end_address_hint);
  void set_byte_size(subroutine& function);
  void check_stop() const;
  std::vector<uint64_t> discover_subroutine_starts();

  std::optional<uint64_t> get_jump_target(
    const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operands, uint64_t current_address
  ) const;

  const uint8_t* data_;
  size_t size_;
  uint64_t base_address_;
  std::vector<uint64_t> known_starts_;
  std::vector<address_range> address_ranges_;
  bool decode_instructions_{true};
  size_t worker_count_{1};
  std::stop_token stop_token_;
  std::stop_token worker_token_;
  decoder decoder_;
};
