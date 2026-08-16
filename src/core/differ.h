#pragma once

#include <memory>
#include <string>
#include <vector>
#include "analyzer.h"
#include "logger.h"
#include "parser.h"

class binary_differ {
  public:
  struct compare_options {
    double match_threshold{0.7};
    double fallback_threshold{0.5};
    uint64_t address_radius{0x20000};
    size_t pair_limit{5'000'000};
    bool decode_instructions{true};
    size_t fallback_limit{4};
    double quick_threshold{0.97};
    bool generate_details{true};
  };

  struct diff_result {
    std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>> matches;
    std::vector<subroutine_analyzer::subroutine> unmatched_primary;
    std::vector<subroutine_analyzer::subroutine> unmatched_secondary;
    size_t primary_count{0};
    size_t secondary_count{0};
    size_t skipped_candidates{0};
  };

  binary_differ(const std::string& primary_path, const std::string& secondary_path);
  binary_differ(const std::string& primary_path, const std::string& secondary_path, compare_options options);

  diff_result compare();

  private:
  struct subroutine_match {
    size_t primary_index{};
    size_t secondary_index{};
    double similarity{};
    std::vector<std::string> diff_details;
  };

  double score_subroutines(
    const subroutine_analyzer::subroutine& s1, const subroutine_analyzer::subroutine& s2,
    std::vector<std::string>* diff_details = nullptr
  );

  std::vector<subroutine_match> match_subroutines(
    const std::vector<subroutine_analyzer::subroutine>& primary_subroutines,
    const std::vector<subroutine_analyzer::subroutine>& secondary_subroutines
  );

  std::vector<std::pair<char, std::string>>
  diff_instructions(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2);

  std::vector<std::string> get_lcs(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2);

  std::unique_ptr<binary_parser> primary_;
  std::unique_ptr<binary_parser> secondary_;
  compare_options options_;
  size_t skipped_candidates_{0};
};
