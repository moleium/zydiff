#include <algorithm>
#include <charconv>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "core/differ.h"
#include "core/strings.h"

struct display_options {
  bool summary_only{false};
  bool show_unchanged{false};
  size_t limit{100};
};

struct cli_options {
  display_options display;
  bool include_instructions{true};
  bool strings{false};
  std::string primary_path;
  std::string secondary_path;
};

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
      options.include_instructions = false;
    } else if (arg == "--strings") {
      options.strings = true;
    } else if (arg == "--no-instructions") {
      options.include_instructions = false;
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
    } else if (arg.starts_with('-')) {
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

std::string_view change_label(binary_differ::change_type change) {
  switch (change) {
    case binary_differ::change_type::unchanged:
      return "unchanged";
    case binary_differ::change_type::values_changed:
      return "values/offsets changed";
    case binary_differ::change_type::flow_changed:
      return "control flow changed";
    case binary_differ::change_type::instructions_changed:
      return "instructions changed";
  }
  std::unreachable();
}

void print_results(const binary_differ::diff_result& result, const display_options& options) {
  using namespace std::literals;

  constexpr auto green = "\033[32m"sv;
  constexpr auto red = "\033[31m"sv;
  constexpr auto yellow = "\033[33m"sv;
  constexpr auto blue = "\033[34m"sv;
  constexpr auto reset = "\033[0m"sv;

  size_t modified_count = 0;
  size_t unchanged_count = 0;
  size_t value_count = 0;
  size_t flow_count = 0;
  size_t instruction_count = 0;
  for (const auto& match : result.matches) {
    switch (match.change) {
      case binary_differ::change_type::unchanged:
        ++unchanged_count;
        break;
      case binary_differ::change_type::values_changed:
        ++modified_count;
        ++value_count;
        break;
      case binary_differ::change_type::flow_changed:
        ++modified_count;
        ++flow_count;
        break;
      case binary_differ::change_type::instructions_changed:
        ++modified_count;
        ++instruction_count;
        break;
    }
  }

  std::println("{}+ {} subroutines added{}", green, result.unmatched_secondary.size(), reset);
  std::println("{}- {} subroutines removed{}", red, result.unmatched_primary.size(), reset);
  std::println("{}~ {} subroutines modified{}", yellow, modified_count, reset);
  std::println("  instructions changed: {}", instruction_count);
  std::println("  control flow changed: {}", flow_count);
  std::println("  values/offsets changed only: {}", value_count);
  std::println("= {} subroutines unchanged\n", unchanged_count);
  std::println("primary subroutines: {}", result.primary_count);
  std::println("secondary subroutines: {}", result.secondary_count);
  if (result.skipped_candidates > 0) {
    std::println("skipped broad match candidates: {}", result.skipped_candidates);
  }

  if (options.summary_only) {
    return;
  }

  if (!result.unmatched_secondary.empty()) {
    std::println(":: Added Subroutines (in secondary only)");
    const auto print_count = std::min(options.limit, result.unmatched_secondary.size());
    for (size_t i = 0; i < print_count; ++i) {
      const auto& sub = result.unmatched_secondary[i];
      std::println("{}+ Added: subroutine at {}{:08x}{}", green, blue, sub.start_address, reset);
    }
    print_limit_notice("added subroutines", print_count, result.unmatched_secondary.size());
  }

  if (!result.unmatched_primary.empty()) {
    std::println("\n:: Removed Subroutines (in primary only)");
    const auto print_count = std::min(options.limit, result.unmatched_primary.size());
    for (size_t i = 0; i < print_count; ++i) {
      const auto& sub = result.unmatched_primary[i];
      std::println("{}- Removed: subroutine at {}{:08x}{}", red, blue, sub.start_address, reset);
    }
    print_limit_notice("removed subroutines", print_count, result.unmatched_primary.size());
  }

  if (!result.matches.empty()) {
    size_t printed = 0;
    for (const auto& match : result.matches) {
      const auto& primary = match.primary;
      const auto& secondary = match.secondary;
      const bool is_unchanged = match.change == binary_differ::change_type::unchanged;

      if (is_unchanged) {
        if (!options.show_unchanged) {
          continue;
        }
        if (printed >= options.limit) {
          continue;
        }
        std::println(
          "= Unchanged: {}{:08x}{} -> {}{:08x}{}", blue, primary.start_address, reset, blue, secondary.start_address,
          reset
        );
        ++printed;
        continue;
      }

      if (printed >= options.limit) {
        continue;
      }

      std::println(
        "{}~ Modified [{}]: {}{:08x}{} -> {}{:08x}{}", yellow, change_label(match.change), blue, primary.start_address,
        reset, blue, secondary.start_address, reset
      );
      ++printed;

      const auto block_diffs = binary_differ::diff_blocks(match);
      if (!block_diffs) {
        std::println("    instruction details unavailable");
        continue;
      }
      for (const auto& block : *block_diffs) {
        for (const auto& instruction : block.instructions) {
          switch (instruction.type) {
            case binary_differ::edit_type::unchanged:
              std::println("      {}", *instruction.primary);
              break;
            case binary_differ::edit_type::changed:
              std::println("  {}-{} {}{}", red, reset, red, *instruction.primary, reset);
              std::println("  {}+{} {}{}", green, reset, green, *instruction.secondary, reset);
              break;
            case binary_differ::edit_type::added:
              std::println("  {}+{} {}{}", green, reset, green, *instruction.secondary, reset);
              break;
            case binary_differ::edit_type::removed:
              std::println("  {}-{} {}{}", red, reset, red, *instruction.primary, reset);
              break;
          }
        }
      }
    }
    print_limit_notice("matched subroutines", printed, options.show_unchanged ? result.matches.size() : modified_count);
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
    diff_options.include_instructions = options->include_instructions;
    binary_differ differ(options->primary_path, options->secondary_path, diff_options);
    auto result = differ.compare();
    print_results(result, options->display);
  } catch (const std::exception& e) {
    std::println(stderr, "Error: {}", e.what());
    return 1;
  }

  return 0;
}
