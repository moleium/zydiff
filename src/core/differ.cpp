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
    LOG("Failed to get text sections\n");
    return result;
  }

  LOG("Text section sizes - Primary: %zu, Secondary: %zu\n", primary_text->size, secondary_text->size);

  subroutine_analyzer primary_analyzer(
    primary_text->data.data(), primary_text->size, primary_->get_image_base() + primary_text->virtual_address
  );

  subroutine_analyzer secondary_analyzer(
    secondary_text->data.data(), secondary_text->size, secondary_->get_image_base() + secondary_text->virtual_address
  );

  auto primary_subroutines = primary_analyzer.get_subroutines();
  auto secondary_subroutines = secondary_analyzer.get_subroutines();

  LOG(
    "Subroutines identified - Primary: %zu, Secondary: %zu\n", primary_subroutines.size(), secondary_subroutines.size()
  );

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

    double block_similarity =
      1.0 - static_cast<double>(distance) / std::max(bb1.instructions.size(), bb2.instructions.size());

    if (block_similarity > 0.3) {
      LOG("Block %zu similarity: %f\n", i, block_similarity);
    }

    if (block_similarity < 0.3) {
      double best_similarity = 0.0;
      for (const auto& other_bb : s2.basic_blocks) {
        auto curr_distance = subroutine_analyzer::levenshtein_distance(bb1.instructions, other_bb.instructions);
        double curr_similarity =
          1.0 - static_cast<double>(curr_distance) / std::max(bb1.instructions.size(), other_bb.instructions.size());

        if (curr_similarity > best_similarity) {
          best_similarity = curr_similarity;
          block_similarity = curr_similarity;
        }
      }
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

  return compared_blocks > 0 ? total_similarity / compared_blocks : 0.0;
}

auto binary_differ::get_instruction_differences(
  const std::vector<std::string>& seq1, const std::vector<std::string>& seq2
) -> std::pair<std::vector<std::string>, std::vector<std::string>> {
  std::vector<std::string> removed, added;

  auto lcs = get_lcs(seq1, seq2);

  size_t i = 0, j = 0, k = 0;
  while (i < seq1.size() || j < seq2.size()) {
    if (k < lcs.size() && i < seq1.size() && seq1[i] == lcs[k]) {
      i++;
      k++;
    } else if (k < lcs.size() && j < seq2.size() && seq2[j] == lcs[k]) {
      j++;
      k++;
    } else {
      if (i < seq1.size()) {
        removed.push_back(seq1[i++]);
      }
      if (j < seq2.size()) {
        added.push_back(seq2[j++]);
      }
    }
  }

  return {removed, added};
}

std::vector<std::string>
binary_differ::get_lcs(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2) {
  std::vector<std::vector<size_t>> dp(seq1.size() + 1, std::vector<size_t>(seq2.size() + 1, 0));

  for (size_t i = 1; i <= seq1.size(); i++) {
    for (size_t j = 1; j <= seq2.size(); j++) {
      if (seq1[i - 1] == seq2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  std::vector<std::string> lcs;
  size_t i = seq1.size(), j = seq2.size();
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
  std::reverse(lcs.begin(), lcs.end());
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

  std::vector<std::tuple<double, size_t, size_t, std::vector<std::string>>> similarities;
  std::vector<const subroutine_analyzer::subroutine*> p_subroutines_ptrs;
  std::vector<const subroutine_analyzer::subroutine*> s_subroutines_ptrs;

  for (auto const& [fingerprint, p_bucket] : primary_map) {
    auto s_it = secondary_map.find(fingerprint);
    if (s_it != secondary_map.end()) {
      const auto& s_bucket = s_it->second;
      LOG(
        "\nComparing bucket with fingerprint (%zu blocks, %zu instructions): %zu primary vs %zu secondary "
        "subroutines\n",
        fingerprint.first, fingerprint.second, p_bucket.size(), s_bucket.size()
      );

      p_subroutines_ptrs.assign(p_bucket.begin(), p_bucket.end());
      s_subroutines_ptrs.assign(s_bucket.begin(), s_bucket.end());

      for (size_t i = 0; i < p_subroutines_ptrs.size(); ++i) {
        for (size_t j = 0; j < s_subroutines_ptrs.size(); ++j) {
          LOG(
            "Comparing P[idx %zu](0x%llx) vs S[idx %zu](0x%llx)\n", i, p_subroutines_ptrs[i]->start_address, j,
            s_subroutines_ptrs[j]->start_address
          );

          std::vector<std::string> diff_details;
          double similarity = get_subroutine_similarity(*p_subroutines_ptrs[i], *s_subroutines_ptrs[j], diff_details);
          LOG("Similarity: %f\n", similarity);

          if (similarity > 0.7) {
            size_t original_primary_idx = std::distance(primary_subroutines.data(), p_subroutines_ptrs[i]);
            size_t original_secondary_idx = std::distance(secondary_subroutines.data(), s_subroutines_ptrs[j]);

            similarities.emplace_back(
              similarity, original_primary_idx, original_secondary_idx, std::move(diff_details)
            );
          }
        }
      }
    }
  }

  std::sort(
    similarities.begin(), similarities.end(),
    std::greater<std::tuple<double, size_t, size_t, std::vector<std::string>>>()
  );

  std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>> matches;
  std::set<size_t> matched_primary_indices, matched_secondary_indices;
  for (const auto& [similarity, primary_idx, secondary_idx, details] : similarities) {
    if (matched_primary_indices.contains(primary_idx) || matched_secondary_indices.contains(secondary_idx)) {
      continue;
    }

    auto primary_copy = primary_subroutines[primary_idx];
    primary_copy.similarity_score = similarity;
    primary_copy.diff_details = details;

    matches.emplace_back(std::move(primary_copy), secondary_subroutines[secondary_idx]);
    matched_primary_indices.insert(primary_idx);
    matched_secondary_indices.insert(secondary_idx);
  }

  return matches;
}
