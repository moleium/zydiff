#include <algorithm>
#include <map>
#include <print>
#include <string>
#include <string_view>
#include <vector>
#include "core/differ.h"
#include "logger.h"

struct diff_line {
  char op;
  std::string text;
};

std::vector<diff_line>
generate_diff(const std::vector<std::string>& primary, const std::vector<std::string>& secondary) {
  const size_t m = primary.size();
  const size_t n = secondary.size();
  std::vector<std::vector<size_t>> lcs_table(m + 1, std::vector<size_t>(n + 1, 0));

  for (size_t i = 1; i <= m; ++i) {
    for (size_t j = 1; j <= n; ++j) {
      if (primary[i - 1] == secondary[j - 1]) {
        lcs_table[i][j] = lcs_table[i - 1][j - 1] + 1;
      } else {
        lcs_table[i][j] = std::max(lcs_table[i - 1][j], lcs_table[i][j - 1]);
      }
    }
  }

  std::vector<diff_line> diff;
  size_t i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && primary[i - 1] == secondary[j - 1]) {
      diff.push_back({' ', primary[i - 1]});
      --i;
      --j;
    } else if (j > 0 && (i == 0 || lcs_table[i][j - 1] >= lcs_table[i - 1][j])) {
      diff.push_back({'+', secondary[j - 1]});
      --j;
    } else if (i > 0 && (j == 0 || lcs_table[i - 1][j] > lcs_table[i][j - 1])) {
      diff.push_back({'-', primary[i - 1]});
      --i;
    }
  }

  std::reverse(diff.begin(), diff.end());
  return diff;
}

void format_results(const binary_differ::diff_result& result) {
  using namespace std::literals;
  using subroutine_pair = std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>;

  constexpr auto green = "\033[32m"sv;
  constexpr auto red = "\033[31m"sv;
  constexpr auto yellow = "\033[33m"sv;
  constexpr auto blue = "\033[34m"sv;
  constexpr auto reset = "\033[0m"sv;

  auto truly_unmatched_primary = result.unmatched_primary;
  auto truly_unmatched_secondary = result.unmatched_secondary;
  std::vector<subroutine_pair> modified_result;

  std::map<uint64_t, subroutine_analyzer::subroutine> secondary_map;
  for (const auto& sub : truly_unmatched_secondary) {
    secondary_map[sub.start_address] = sub;
  }

  auto primary_it =
    std::remove_if(truly_unmatched_primary.begin(), truly_unmatched_primary.end(), [&](const auto& primary_sub) {
      if (auto it = secondary_map.find(primary_sub.start_address); it != secondary_map.end()) {
        modified_result.emplace_back(primary_sub, it->second);
        secondary_map.erase(it);
        return true;
      }
      return false;
    });
  truly_unmatched_primary.erase(primary_it, truly_unmatched_primary.end());

  truly_unmatched_secondary.clear();
  for (const auto& [addr, sub] : secondary_map) {
    truly_unmatched_secondary.push_back(sub);
  }
  modified_result.insert(modified_result.end(), result.matched_subroutines.begin(), result.matched_subroutines.end());

  size_t modified_count = 0;
  size_t unchanged_count = 0;
  for (const auto& [primary, secondary] : modified_result) {
    if (primary.start_address == secondary.start_address &&
        primary.basic_blocks.size() == secondary.basic_blocks.size() && primary.similarity_score == 1.0) {
      unchanged_count++;
    } else {
      modified_count++;
    }
  }

  std::println("{}+ {} subroutines added{}", green, truly_unmatched_secondary.size(), reset);
  std::println("{}- {} subroutines removed{}", red, truly_unmatched_primary.size(), reset);
  std::println("{}~ {} subroutines modified{}", yellow, modified_count, reset);
  std::println("= {} subroutines unchanged\n", unchanged_count);

  if (!truly_unmatched_secondary.empty()) {
    std::println(":: Added Subroutines (in secondary only)");
    for (const auto& sub : truly_unmatched_secondary) {
      std::println("{}+ Added: subroutine at {}{:08x}{}", green, blue, sub.start_address, reset);
    }
  }

  if (!truly_unmatched_primary.empty()) {
    std::println("\n:: Removed Subroutines (in primary only)");
    for (const auto& sub : truly_unmatched_primary) {
      std::println("{}- Removed: subroutine at {}{:08x}{}", red, blue, sub.start_address, reset);
    }
  }

  if (!modified_result.empty()) {
    for (const auto& [primary, secondary] : modified_result) {
      bool is_unchanged = primary.similarity_score == 1.0 && primary.start_address == secondary.start_address &&
                          primary.basic_blocks.size() == secondary.basic_blocks.size();

      if (is_unchanged) {
        std::println(
          "= Unchanged: {}{:08x}{} -> {}{:08x}{}", blue, primary.start_address, reset, blue, secondary.start_address,
          reset
        );
        continue;
      }

      std::println(
        "{}~ Modified: {}{:08x}{} -> {}{:08x}{}", yellow, blue, primary.start_address, reset, blue,
        secondary.start_address, reset
      );

      size_t common_blocks = std::min(primary.basic_blocks.size(), secondary.basic_blocks.size());
      for (size_t i = 0; i < common_blocks; ++i) {
        const auto& p_block = primary.basic_blocks[i];
        const auto& s_block = secondary.basic_blocks[i];
        auto diff = generate_diff(p_block.instructions, s_block.instructions);

        for (const auto& line : diff) {
          switch (line.op) {
            case ' ':
              std::println("    {} {}", line.op, line.text);
              break;
            case '+':
              std::println("  {}{}{} {}{}", green, line.op, reset, green, line.text, reset);
              break;
            case '-':
              std::println("  {}{}{} {}{}", red, line.op, reset, red, line.text, reset);
              break;
          }
        }
      }

      for (size_t i = common_blocks; i < primary.basic_blocks.size(); ++i) {
        for (const auto& instr : primary.basic_blocks[i].instructions) {
          std::println("  {}{}- {}{}", red, reset, red, instr, reset);
        }
      }
      for (size_t i = common_blocks; i < secondary.basic_blocks.size(); ++i) {
        for (const auto& instr : secondary.basic_blocks[i].instructions) {
          std::println("  {}{}+ {}{}", green, reset, green, instr, reset);
        }
      }
    }
  }
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::println(stderr, "Usage: {} <primary_binary> <secondary_binary>", argv[0]);
    return 1;
  }

  try {
    binary_differ differ(argv[1], argv[2]);
    auto result = differ.compare();
    format_results(result);
  } catch (const std::exception& e) {
    std::println(stderr, "Error: {}", e.what());
    return 1;
  }

  return 0;
}

