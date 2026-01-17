#include "differ.h"
#include <algorithm>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include <vector>

binary_differ::binary_differ(const std::string& primary_path, const std::string& secondary_path) :
    primary_(std::make_unique<binary_parser>(primary_path)),
    secondary_(std::make_unique<binary_parser>(secondary_path)) {
}

binary_differ::diff_result binary_differ::compare() {
  diff_result result;

  auto primary_text = primary_->get_text_section();
  auto secondary_text = secondary_->get_text_section();

  if (!primary_text || !secondary_text) {
    std::println(stderr, "error: failed to get text sections");
    return result;
  }

  subroutine_analyzer primary_analyzer(
    primary_text->data.data(), primary_text->size, primary_->get_image_base() + primary_text->virtual_address
  );

  subroutine_analyzer secondary_analyzer(
    secondary_text->data.data(), secondary_text->size, secondary_->get_image_base() + secondary_text->virtual_address
  );

  auto primary_subroutines = primary_analyzer.get_subroutines();
  auto secondary_subroutines = secondary_analyzer.get_subroutines();

  result.matched_subroutines = match_subroutines(primary_subroutines, secondary_subroutines);

  std::set<uint64_t> matched_primary, matched_secondary;
  for (const auto& [p, s] : result.matched_subroutines) {
    matched_primary.insert(p.start_address);
    matched_secondary.insert(s.start_address);
  }

  for (const auto& sub : primary_subroutines) {
    if (!matched_primary.contains(sub.start_address)) {
      result.unmatched_primary.push_back(sub);
    }
  }

  for (const auto& sub : secondary_subroutines) {
    if (!matched_secondary.contains(sub.start_address)) {
      result.unmatched_secondary.push_back(sub);
    }
  }

  return result;
}

double binary_differ::get_subroutine_similarity(
  const subroutine_analyzer::subroutine& s1, const subroutine_analyzer::subroutine& s2,
  std::vector<std::string>& diff_details
) {
  double total_similarity = 0.0;
  int compared_blocks = 0;

  for (size_t i = 0; i < std::min(s1.basic_blocks.size(), s2.basic_blocks.size()); i++) {
    const auto& bb1 = s1.basic_blocks[i];
    const auto& bb2 = s2.basic_blocks[i];

    auto distance = subroutine_analyzer::levenshtein_distance(bb1.instructions, bb2.instructions);

    if (bb1.instructions.empty() && bb2.instructions.empty()) {
      continue;
    }

    double block_similarity =
      1.0 - static_cast<double>(distance) / std::max({size_t{1}, bb1.instructions.size(), bb2.instructions.size()});

    // if blocks at the same index are very different
    // try to find a better match elsewhere
    if (block_similarity < 0.3) {
      double best_similarity = block_similarity;
      for (const auto& other_bb : s2.basic_blocks) {
        auto curr_distance = subroutine_analyzer::levenshtein_distance(bb1.instructions, other_bb.instructions);
        double curr_similarity = 1.0 - static_cast<double>(curr_distance) /
                                         std::max({size_t{1}, bb1.instructions.size(), other_bb.instructions.size()});

        if (curr_similarity > best_similarity) {
          best_similarity = curr_similarity;
        }
      }
      block_similarity = best_similarity;
    }

    if (block_similarity > 0.5) {
      total_similarity += block_similarity;
      compared_blocks++;

      if (block_similarity < 1.0) {
        std::string diff_detail = std::format(
          "Block at 0x{:x} -> 0x{:x} ({:.1f}% similar):\n", bb1.start_address, bb2.start_address, block_similarity * 100
        );

        auto [removed, added] = get_instruction_differences(bb1.instructions, bb2.instructions);
        if (!removed.empty()) {
          diff_detail += "  Removed:\n";
          for (const auto& instr : removed) {
            diff_detail += "    - " + instr + "\n";
          }
        }
        if (!added.empty()) {
          diff_detail += "  Added:\n";
          for (const auto& instr : added) {
            diff_detail += "    + " + instr + "\n";
          }
        }

        diff_details.emplace_back(std::move(diff_detail));
      }
    }
  }

  return compared_blocks > 0 ? total_similarity / static_cast<double>(compared_blocks) : 0.0;
}

auto binary_differ::get_instruction_differences(
  const std::vector<std::string>& seq1, const std::vector<std::string>& seq2
) -> std::pair<std::vector<std::string>, std::vector<std::string>> {
  std::vector<std::string> removed, added;
  auto lcs = get_lcs(seq1, seq2);

  size_t i = 0;
  size_t j = 0;
  size_t k = 0;

  while (k < lcs.size()) {
    // process removals in seq1 until the next lcs element is found
    while (i < seq1.size() && seq1[i] != lcs[k]) {
      removed.push_back(seq1[i]);
      i++;
    }

    // process additions in seq2 until the next lcs element is found
    while (j < seq2.size() && seq2[j] != lcs[k]) {
      added.push_back(seq2[j]);
      j++;
    }

    // at this point, seq1[i] == seq2[j] == lcs[k]
    if (i < seq1.size()) {
      i++;
    }
    if (j < seq2.size()) {
      j++;
    }
    k++;
  }

  while (i < seq1.size()) {
    removed.push_back(seq1[i]);
    i++;
  }
  while (j < seq2.size()) {
    added.push_back(seq2[j]);
    j++;
  }

  return {removed, added};
}

std::vector<std::string>
binary_differ::get_lcs(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2) {
  const auto m = seq1.size();
  const auto n = seq2.size();
  std::vector<std::vector<size_t>> dp(m + 1, std::vector<size_t>(n + 1, 0));

  for (size_t i = 1; i <= m; i++) {
    for (size_t j = 1; j <= n; j++) {
      if (seq1[i - 1] == seq2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  std::vector<std::string> lcs;
  lcs.reserve(dp[m][n]);
  size_t i = m, j = n;
  while (i > 0 && j > 0) {
    if (seq1[i - 1] == seq2[j - 1]) {
      lcs.push_back(seq1[i - 1]);
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }
  std::ranges::reverse(lcs);
  return lcs;
}

std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>>
binary_differ::match_subroutines(
  const std::vector<subroutine_analyzer::subroutine>& primary_subroutines,
  const std::vector<subroutine_analyzer::subroutine>& secondary_subroutines
) {
  std::unordered_map<fingerprint, std::vector<const subroutine_analyzer::subroutine*>, fingerprint_hash> primary_map;
  for (const auto& sub : primary_subroutines) {
    primary_map[sub.fingerprint].push_back(&sub);
  }

  std::unordered_map<fingerprint, std::vector<const subroutine_analyzer::subroutine*>, fingerprint_hash> secondary_map;
  for (const auto& sub : secondary_subroutines) {
    secondary_map[sub.fingerprint].push_back(&sub);
  }

  std::vector<std::tuple<
    double, const subroutine_analyzer::subroutine*, const subroutine_analyzer::subroutine*, std::vector<std::string>>>
    similarities;

  for (auto const& [fingerprint, p_bucket] : primary_map) {
    auto s_it = secondary_map.find(fingerprint);
    if (s_it != secondary_map.end()) {
      const auto& s_bucket = s_it->second;

      for (const auto* p_sub : p_bucket) {
        for (const auto* s_sub : s_bucket) {
          std::vector<std::string> diff_details;
          double similarity = get_subroutine_similarity(*p_sub, *s_sub, diff_details);

          if (similarity > 0.7) {
            similarities.emplace_back(similarity, p_sub, s_sub, std::move(diff_details));
          }
        }
      }
    }
  }

  std::ranges::sort(similarities, std::ranges::greater{}, [](const auto& t) {
    return std::get<0>(t);
  });

  std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>> matches;
  std::set<uint64_t> matched_primary_addrs, matched_secondary_addrs;
  for (const auto& [similarity, primary_sub, secondary_sub, details] : similarities) {
    if (matched_primary_addrs.contains(primary_sub->start_address) ||
        matched_secondary_addrs.contains(secondary_sub->start_address)) {
      continue;
    }

    auto primary_copy = *primary_sub;
    primary_copy.similarity_score = similarity;
    primary_copy.diff_details = details;

    matches.emplace_back(std::move(primary_copy), *secondary_sub);
    matched_primary_addrs.insert(primary_sub->start_address);
    matched_secondary_addrs.insert(secondary_sub->start_address);
  }

  return matches;
}
