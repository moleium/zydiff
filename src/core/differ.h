#pragma once

#include <memory>
#include <string>
#include <vector>
#include "analyzer.h"
#include "logger.h"
#include "parser.h"

class binary_differ {
  public:
  struct diff_result {
    std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>> matched_subroutines;
    std::vector<subroutine_analyzer::subroutine> unmatched_primary;
    std::vector<subroutine_analyzer::subroutine> unmatched_secondary;
  };

  binary_differ(const std::string& primary_path, const std::string& secondary_path);

  diff_result compare();

  private:
  double get_subroutine_similarity(
          const subroutine_analyzer::subroutine& s1, const subroutine_analyzer::subroutine& s2,
          std::vector<std::string>& diff_details
  );

  std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>> match_subroutines(
          const std::vector<subroutine_analyzer::subroutine>& primary_subroutines,
          const std::vector<subroutine_analyzer::subroutine>& secondary_subroutines
  );

  std::pair<std::vector<std::string>, std::vector<std::string>>
  get_instruction_differences(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2);

  std::vector<std::string> get_lcs(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2);

  std::unique_ptr<binary_parser> primary_;
  std::unique_ptr<binary_parser> secondary_;
};
