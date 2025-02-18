#include "differ.h"
#include <algorithm>
#include <unordered_map>

BinaryDiffer::BinaryDiffer(const std::string& primary_path, const std::string& secondary_path)
    : primary_(std::make_unique<BinaryParser>(primary_path)),
      secondary_(std::make_unique<BinaryParser>(secondary_path)) {}

auto BinaryDiffer::Compare() -> DiffResult {
  DiffResult result;
  
  auto primary_text = primary_->GetTextSection();
  auto secondary_text = secondary_->GetTextSection();
  
  if (!primary_text || !secondary_text) {
    LOG("Failed to get text sections\n");
    return result;
  }

  LOG("Text section sizes - Primary: %zu, Secondary: %zu\n", 
         primary_text->size, secondary_text->size);

  FunctionAnalyzer primary_analyzer(
      primary_text->data.data(),
      primary_text->size,
      primary_->GetImageBase() + primary_text->virtual_address);
      
  FunctionAnalyzer secondary_analyzer(
      secondary_text->data.data(),
      secondary_text->size,
      secondary_->GetImageBase() + secondary_text->virtual_address);

  auto primary_funcs = primary_analyzer.IdentifyFunctions();
  auto secondary_funcs = secondary_analyzer.IdentifyFunctions();

  LOG("Functions identified - Primary: %zu, Secondary: %zu\n",
         primary_funcs.size(), secondary_funcs.size());

  result.matched_functions = MatchFunctions(primary_funcs, secondary_funcs);

  std::set<uint64_t> matched_primary, matched_secondary;
  for (const auto& [p, s] : result.matched_functions) {
    matched_primary.insert(p.start_address);
    matched_secondary.insert(s.start_address);
  }

  for (const auto& func : primary_funcs) {
    if (!matched_primary.contains(func.start_address)) {
      result.unmatched_primary.push_back(func);
    }
  }

  for (const auto& func : secondary_funcs) {
    if (!matched_secondary.contains(func.start_address)) {
      result.unmatched_secondary.push_back(func);
    }
  }

  return result;
}

auto BinaryDiffer::CalculateFunctionSimilarity(
    const FunctionAnalyzer::Function& f1,
    const FunctionAnalyzer::Function& f2,
    std::vector<std::string>& diff_details) -> double {
  double total_similarity = 0.0;
  int compared_blocks = 0;

  for (size_t i = 0; i < std::min(f1.basic_blocks.size(), f2.basic_blocks.size()); i++) {
    const auto& bb1 = f1.basic_blocks[i];
    const auto& bb2 = f2.basic_blocks[i];

    auto distance = FunctionAnalyzer::LevenshteinDistance(
        bb1.instructions, bb2.instructions);

    double block_similarity =
        1.0 - static_cast<double>(distance) /
                  std::max(bb1.instructions.size(), bb2.instructions.size());

    if (block_similarity > 0.3) {
      LOG("  Block %zu similarity: %f\n", i, block_similarity);
    }

    // If blocks are very dissimilar, they might be reordered
    if (block_similarity < 0.3) {
      // Try to find a better matching block
      double best_similarity = 0.0;
      for (const auto& other_bb : f2.basic_blocks) {
        auto curr_distance = FunctionAnalyzer::LevenshteinDistance(
            bb1.instructions, other_bb.instructions);
        double curr_similarity = 1.0 - static_cast<double>(curr_distance) / 
            std::max(bb1.instructions.size(), other_bb.instructions.size());
        
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
            "Block at 0x{:x} -> 0x{:x} ({:.1f}% similar):\n",
            bb1.start_address, bb2.start_address, block_similarity * 100);

        auto [removed, added] =
            GetInstructionDifferences(bb1.instructions, bb2.instructions);
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

// checks two sequences of instructions and figures what's been added or removed
// by comparing them to their longest common subsequence (LCS).
auto BinaryDiffer::GetInstructionDifferences(
    const std::vector<std::string>& seq1,
    const std::vector<std::string>& seq2) 
    -> std::pair<std::vector<std::string>, std::vector<std::string>> {
  std::vector<std::string> removed, added;
  
  auto lcs = GetLCS(seq1, seq2);
  
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

// get the longest common subsequence (LCS) of two sequences of instructions.
auto BinaryDiffer::GetLCS(
    const std::vector<std::string>& seq1,
    const std::vector<std::string>& seq2) 
    -> std::vector<std::string> {
  std::vector<std::vector<size_t>> dp(
      seq1.size() + 1, 
      std::vector<size_t>(seq2.size() + 1, 0));

  for (size_t i = 1; i <= seq1.size(); i++) {
    for (size_t j = 1; j <= seq2.size(); j++) {
      if (seq1[i-1] == seq2[j-1]) {
        dp[i][j] = dp[i-1][j-1] + 1;
      } else {
        dp[i][j] = std::max(dp[i-1][j], dp[i][j-1]);
      }
    }
  }

  std::vector<std::string> lcs;
  size_t i = seq1.size(), j = seq2.size();
  while (i > 0 && j > 0) {
    if (seq1[i-1] == seq2[j-1]) {
      lcs.push_back(seq1[i-1]);
      i--;
      j--;
    } else if (dp[i-1][j] > dp[i][j-1]) {
      i--;
    } else {
      j--;
    }
  }
  std::reverse(lcs.begin(), lcs.end());
  return lcs;
}

auto BinaryDiffer::MatchFunctions(
    const std::vector<FunctionAnalyzer::Function> &primary_funcs,
    const std::vector<FunctionAnalyzer::Function> &secondary_funcs)
    -> std::vector<
        std::pair<FunctionAnalyzer::Function, FunctionAnalyzer::Function>> {
  std::vector<std::pair<FunctionAnalyzer::Function, FunctionAnalyzer::Function>>
      matches;

  std::vector<std::tuple<double, size_t, size_t, std::vector<std::string>>>
      similarities;
  for (size_t i = 0; i < primary_funcs.size(); i++) {
    for (size_t j = 0; j < secondary_funcs.size(); j++) {
      auto size_ratio =
          static_cast<double>(primary_funcs[i].basic_blocks.size()) /
          secondary_funcs[j].basic_blocks.size();
      if (size_ratio < 0.5 || size_ratio > 2.0) {
        continue;
      }

      LOG("\nComparing functions - Primary[%zu](0x%llx) vs "
             "Secondary[%zu](0x%llx)\n",
             i, primary_funcs[i].start_address, j,
             secondary_funcs[j].start_address);
      
      std::vector<std::string> diff_details;
      auto similarity = CalculateFunctionSimilarity(
          primary_funcs[i], secondary_funcs[j], diff_details);
      LOG("Overall similarity: %f\n", similarity);
      if (similarity > 0.7) {
        similarities.emplace_back(similarity, i, j, std::move(diff_details));
      }
    }
  }

  std::sort(
      similarities.begin(), similarities.end(),
      std::greater<
          std::tuple<double, size_t, size_t, std::vector<std::string>>>());

  std::set<size_t> matched_primary, matched_secondary;
  for (const auto &[similarity, primary_idx, secondary_idx, details] :
       similarities) {
    if (matched_primary.contains(primary_idx) ||
        matched_secondary.contains(secondary_idx)) {
      continue;
    }

    auto primary = primary_funcs[primary_idx];
    primary.similarity_score = similarity;
    primary.diff_details = details;
    matches.emplace_back(std::move(primary), secondary_funcs[secondary_idx]);
    matched_primary.insert(primary_idx);
    matched_secondary.insert(secondary_idx);
  }

  return matches;
}