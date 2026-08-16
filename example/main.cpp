#include <algorithm>
#include <charconv>
#include <map>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>
#include "core/differ.h"
#include "core/strings.h"
#include "logger.h"

struct diff_line {
  char op;
  std::string text;
};

struct display_options {
  bool summary_only{false};
  bool show_unchanged{false};
  size_t limit{100};
};

struct cli_options {
  display_options display;
  bool decode_instructions{true};
  bool strings{false};
  std::string primary_path;
  std::string secondary_path;
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

void print_usage(std::string_view executable) {
  std::println(
    stderr,
    "Usage: {} [--summary] [--strings] [--no-instructions] [--show-unchanged] [--limit count] <primary_binary> "
    "<secondary_binary>",
    executable
  );
}

auto parse_args(int argc, char* argv[]) -> std::optional<cli_options> {
  cli_options options;
  std::vector<std::string> paths;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--summary") {
      options.display.summary_only = true;
      options.decode_instructions = false;
    } else if (arg == "--strings") {
      options.strings = true;
      options.decode_instructions = false;
    } else if (arg == "--no-instructions") {
      options.decode_instructions = false;
    } else if (arg == "--show-unchanged") {
      options.display.show_unchanged = true;
    } else if (arg == "--limit") {
      if (i + 1 >= argc) {
        return std::nullopt;
      }
      const std::string_view value(argv[++i]);
      size_t parsed_limit = 0;
      const auto* begin = value.data();
      const auto* end = value.data() + value.size();
      auto [ptr, ec] = std::from_chars(begin, end, parsed_limit);
      if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
      }
      options.display.limit = parsed_limit;
    } else if (arg == "--help" || arg == "-h") {
      return std::nullopt;
    } else {
      paths.emplace_back(arg);
    }
  }

  if (paths.size() != 2) {
    return std::nullopt;
  }

  options.primary_path = std::move(paths[0]);
  options.secondary_path = std::move(paths[1]);
  return options;
}

void print_limit_notice(std::string_view label, size_t printed, size_t total) {
  if (printed < total) {
    std::println("  ... {} more {} omitted", total - printed, label);
  }
}

auto trim_string(std::string_view value) -> std::string_view {
  constexpr size_t max_width = 180;
  if (value.size() <= max_width) {
    return value;
  }
  return value.substr(0, max_width);
}

void print_string(char op, const strings::entry& entry) {
  const auto suffix = entry.value.size() > trim_string(entry.value).size() ? "..." : "";
  std::println("{} {:08x} {} {}{}", op, entry.address, entry.section, trim_string(entry.value), suffix);
  if (!entry.xrefs.empty()) {
    std::print("    xrefs:");
    for (const auto xref : entry.xrefs) {
      std::print(" {:08x}", xref);
    }
    std::println();
  }
}

void print_strings(const strings::result& result, const display_options& options) {
  std::println("+ {} strings added", result.added.size());
  std::println("- {} strings removed", result.removed.size());
  std::println("primary strings: {}", result.primary_count);
  std::println("secondary strings: {}", result.secondary_count);

  if (!result.added.empty()) {
    std::println("\n:: Added Strings");
    const auto print_count = std::min(options.limit, result.added.size());
    for (size_t i = 0; i < print_count; ++i) {
      print_string('+', result.added[i]);
    }
    print_limit_notice("added strings", print_count, result.added.size());
  }

  if (!result.removed.empty()) {
    std::println("\n:: Removed Strings");
    const auto print_count = std::min(options.limit, result.removed.size());
    for (size_t i = 0; i < print_count; ++i) {
      print_string('-', result.removed[i]);
    }
    print_limit_notice("removed strings", print_count, result.removed.size());
  }
}

void print_results(const binary_differ::diff_result& result, const display_options& options) {
  using namespace std::literals;
  using subroutine = subroutine_analyzer::subroutine;
  using subroutine_pair = std::pair<const subroutine*, const subroutine*>;

  constexpr auto green = "\033[32m"sv;
  constexpr auto red = "\033[31m"sv;
  constexpr auto yellow = "\033[33m"sv;
  constexpr auto blue = "\033[34m"sv;
  constexpr auto reset = "\033[0m"sv;

  std::vector<const subroutine*> unmatched_primary;
  unmatched_primary.reserve(result.unmatched_primary.size());
  for (const auto& sub : result.unmatched_primary) {
    unmatched_primary.push_back(&sub);
  }

  std::vector<const subroutine*> unmatched_secondary;
  unmatched_secondary.reserve(result.unmatched_secondary.size());
  std::vector<subroutine_pair> matches;
  matches.reserve(result.matches.size());

  std::map<uint64_t, const subroutine*> secondary_map;
  for (const auto& sub : result.unmatched_secondary) {
    secondary_map[sub.start_address] = &sub;
  }

  auto primary_it = std::remove_if(unmatched_primary.begin(), unmatched_primary.end(), [&](const auto* primary_sub) {
    if (auto it = secondary_map.find(primary_sub->start_address); it != secondary_map.end()) {
      matches.emplace_back(primary_sub, it->second);
      secondary_map.erase(it);
      return true;
    }
    return false;
  });
  unmatched_primary.erase(primary_it, unmatched_primary.end());

  for (const auto& [addr, sub] : secondary_map) {
    unmatched_secondary.push_back(sub);
  }
  for (const auto& [primary, secondary] : result.matches) {
    matches.emplace_back(&primary, &secondary);
  }

  size_t modified_count = 0;
  size_t unchanged_count = 0;
  for (const auto& [primary, secondary] : matches) {
    if (primary->similarity_score == 1.0) {
      unchanged_count++;
    } else {
      modified_count++;
    }
  }

  std::println("{}+ {} subroutines added{}", green, unmatched_secondary.size(), reset);
  std::println("{}- {} subroutines removed{}", red, unmatched_primary.size(), reset);
  std::println("{}~ {} subroutines modified{}", yellow, modified_count, reset);
  std::println("= {} subroutines unchanged\n", unchanged_count);
  std::println("primary subroutines: {}", result.primary_count);
  std::println("secondary subroutines: {}", result.secondary_count);
  if (result.skipped_candidates > 0) {
    std::println("skipped broad match candidates: {}", result.skipped_candidates);
  }

  if (options.summary_only) {
    return;
  }

  if (!unmatched_secondary.empty()) {
    std::println(":: Added Subroutines (in secondary only)");
    const auto print_count = std::min(options.limit, unmatched_secondary.size());
    for (size_t i = 0; i < print_count; ++i) {
      const auto* sub = unmatched_secondary[i];
      std::println("{}+ Added: subroutine at {}{:08x}{}", green, blue, sub->start_address, reset);
    }
    print_limit_notice("added subroutines", print_count, unmatched_secondary.size());
  }

  if (!unmatched_primary.empty()) {
    std::println("\n:: Removed Subroutines (in primary only)");
    const auto print_count = std::min(options.limit, unmatched_primary.size());
    for (size_t i = 0; i < print_count; ++i) {
      const auto* sub = unmatched_primary[i];
      std::println("{}- Removed: subroutine at {}{:08x}{}", red, blue, sub->start_address, reset);
    }
    print_limit_notice("removed subroutines", print_count, unmatched_primary.size());
  }

  if (!matches.empty()) {
    size_t printed = 0;
    for (const auto& [primary, secondary] : matches) {
      bool is_unchanged = primary->similarity_score == 1.0;

      if (is_unchanged) {
        if (!options.show_unchanged) {
          continue;
        }
        if (printed >= options.limit) {
          continue;
        }
        std::println(
          "= Unchanged: {}{:08x}{} -> {}{:08x}{}", blue, primary->start_address, reset, blue, secondary->start_address,
          reset
        );
        ++printed;
        continue;
      }

      if (printed >= options.limit) {
        continue;
      }

      std::println(
        "{}~ Modified: {}{:08x}{} -> {}{:08x}{}", yellow, blue, primary->start_address, reset, blue,
        secondary->start_address, reset
      );
      ++printed;

      size_t common_blocks = std::min(primary->basic_blocks.size(), secondary->basic_blocks.size());
      for (size_t i = 0; i < common_blocks; ++i) {
        const auto& p_block = primary->basic_blocks[i];
        const auto& s_block = secondary->basic_blocks[i];
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

      for (size_t i = common_blocks; i < primary->basic_blocks.size(); ++i) {
        for (const auto& instr : primary->basic_blocks[i].instructions) {
          std::println("  {}{}- {}{}", red, reset, red, instr, reset);
        }
      }
      for (size_t i = common_blocks; i < secondary->basic_blocks.size(); ++i) {
        for (const auto& instr : secondary->basic_blocks[i].instructions) {
          std::println("  {}{}+ {}{}", green, reset, green, instr, reset);
        }
      }
    }
    print_limit_notice("matched subroutines", printed, options.show_unchanged ? matches.size() : modified_count);
  }
}

int main(int argc, char* argv[]) {
  auto options = parse_args(argc, argv);
  if (!options) {
    print_usage(argv[0]);
    return 1;
  }

  try {
    if (options->strings) {
      auto result = strings::compare(options->primary_path, options->secondary_path, {});
      print_strings(result, options->display);
      return 0;
    }

    binary_differ::compare_options diff_options;
    diff_options.decode_instructions = options->decode_instructions;
    diff_options.generate_details = false;
    binary_differ differ(options->primary_path, options->secondary_path, diff_options);
    auto result = differ.compare();
    print_results(result, options->display);
  } catch (const std::exception& e) {
    std::println(stderr, "Error: {}", e.what());
    return 1;
  }

  return 0;
}
