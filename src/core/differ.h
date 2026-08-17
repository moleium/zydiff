#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "analyzer.h"
#include "parser.h"

class binary_differ {
  public:
  enum class change_type : uint8_t {
    unchanged,
    values_changed,
    flow_changed,
    instructions_changed,
  };

  enum class edit_type : uint8_t {
    unchanged,
    changed,
    added,
    removed,
  };

  enum class detail_error : uint8_t {
    instructions_unavailable,
  };

  struct instruction_edit {
    edit_type type{edit_type::unchanged};
    std::optional<std::string> primary;
    std::optional<std::string> secondary;
  };

  struct block_diff {
    std::optional<uint64_t> primary_address;
    std::optional<uint64_t> secondary_address;
    std::vector<instruction_edit> instructions;
  };

  struct compare_options {
    double match_threshold{0.7};
    double fallback_threshold{0.5};
    uint64_t address_radius{0x20000};
    size_t pair_limit{5'000'000};
    size_t delta_limit{16};
    bool include_instructions{true};
    size_t fallback_limit{4};
  };

  struct matched_subroutine {
    subroutine_analyzer::subroutine primary;
    subroutine_analyzer::subroutine secondary;
    change_type change{change_type::unchanged};
    double similarity{};
  };

  struct block_match {
    size_t primary_index{};
    size_t secondary_index{};
  };

  struct diff_result {
    std::vector<matched_subroutine> matches;
    std::vector<subroutine_analyzer::subroutine> unmatched_primary;
    std::vector<subroutine_analyzer::subroutine> unmatched_secondary;
    size_t primary_count{0};
    size_t secondary_count{0};
    size_t skipped_candidates{0};
  };

  binary_differ(const std::string& primary_path, const std::string& secondary_path);
  binary_differ(const std::string& primary_path, const std::string& secondary_path, compare_options options);

  diff_result compare();
  static std::vector<block_match>
  match_blocks(const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary);
  static std::expected<std::vector<block_diff>, detail_error>
  diff_blocks(const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary);
  static std::expected<std::vector<block_diff>, detail_error> diff_blocks(const matched_subroutine& match);

  private:
  struct match_index {
    size_t primary_index{};
    size_t secondary_index{};
    double similarity{};
  };

  double score_subroutines(const subroutine_analyzer::subroutine& s1, const subroutine_analyzer::subroutine& s2);

  std::vector<match_index> match_subroutines(
    const std::vector<subroutine_analyzer::subroutine>& primary_subroutines,
    const std::vector<subroutine_analyzer::subroutine>& secondary_subroutines
  );

  std::unique_ptr<binary_parser> primary_;
  std::unique_ptr<binary_parser> secondary_;
  compare_options options_;
  size_t skipped_candidates_{0};
};
