#include "differ.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace {

  [[nodiscard]] auto address_distance(uint64_t lhs, uint64_t rhs) -> uint64_t {
    return lhs > rhs ? lhs - rhs : rhs - lhs;
  }

  [[nodiscard]] auto address_delta(uint64_t lhs, uint64_t rhs) -> int64_t {
    if (rhs >= lhs) {
      const auto delta = rhs - lhs;
      return delta > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ? std::numeric_limits<int64_t>::max()
                                                                                : static_cast<int64_t>(delta);
    }

    const auto delta = lhs - rhs;
    return delta > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ? std::numeric_limits<int64_t>::min()
                                                                              : -static_cast<int64_t>(delta);
  }

  [[nodiscard]] auto add_delta(uint64_t address, int64_t delta) -> std::optional<uint64_t> {
    if (delta >= 0) {
      const auto unsigned_delta = static_cast<uint64_t>(delta);
      if (address > std::numeric_limits<uint64_t>::max() - unsigned_delta) {
        return std::nullopt;
      }
      return address + unsigned_delta;
    }

    const auto unsigned_delta = static_cast<uint64_t>(-delta);
    if (address < unsigned_delta) {
      return std::nullopt;
    }
    return address - unsigned_delta;
  }

  struct subroutine_match_key {
    fingerprint code_fingerprint{};
    size_t byte_size{};
    size_t instruction_count{};

    [[nodiscard]] auto operator==(const subroutine_match_key&) const -> bool = default;
  };

  struct subroutine_match_key_hash {
    [[nodiscard]] auto operator()(const subroutine_match_key& key) const -> size_t {
      auto hash = static_cast<uint64_t>(key.code_fingerprint);
      hash ^= static_cast<uint64_t>(key.byte_size) + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
      hash ^= static_cast<uint64_t>(key.instruction_count) + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
      return static_cast<size_t>(hash);
    }
  };

  [[nodiscard]] auto make_match_key(const subroutine_analyzer::subroutine& sub) -> subroutine_match_key {
    return subroutine_match_key{
      .code_fingerprint = sub.fingerprint,
      .byte_size = sub.byte_size,
      .instruction_count = sub.instruction_count,
    };
  }

} // namespace

binary_differ::binary_differ(const std::string& primary_path, const std::string& secondary_path) :
    binary_differ(primary_path, secondary_path, compare_options{}) {
}

binary_differ::binary_differ(
  const std::string& primary_path, const std::string& secondary_path, compare_options options
) :
    primary_(std::make_unique<binary_parser>(primary_path)),
    secondary_(std::make_unique<binary_parser>(secondary_path)), options_(options) {
}

binary_differ::diff_result binary_differ::compare() {
  diff_result result;
  skipped_pairwise_candidates_ = 0;

  auto primary_text = primary_->get_text_section();
  auto secondary_text = secondary_->get_text_section();

  if (!primary_text || !secondary_text) {
    std::println(stderr, "error: failed to get text sections");
    return result;
  }

  subroutine_analyzer primary_analyzer(
    primary_text->data.data(), primary_text->size, primary_->get_image_base() + primary_text->virtual_address,
    primary_->get_function_starts(), options_.decode_instructions
  );

  subroutine_analyzer secondary_analyzer(
    secondary_text->data.data(), secondary_text->size, secondary_->get_image_base() + secondary_text->virtual_address,
    secondary_->get_function_starts(), options_.decode_instructions
  );

  auto primary_subroutines = primary_analyzer.get_subroutines();
  auto secondary_subroutines = secondary_analyzer.get_subroutines();
  result.primary_subroutine_count = primary_subroutines.size();
  result.secondary_subroutine_count = secondary_subroutines.size();

  result.matched_subroutines = match_subroutines(primary_subroutines, secondary_subroutines);
  result.skipped_pairwise_candidates = skipped_pairwise_candidates_;

  std::set<uint64_t> matched_primary;
  std::set<uint64_t> matched_secondary;
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
  if (!options_.decode_instructions) {
    if (
      s1.instruction_count > 0 && s1.instruction_count == s2.instruction_count &&
      s1.instruction_hash == s2.instruction_hash
    ) {
      return 1.0;
    }
    if (s1.byte_size == s2.byte_size && s1.byte_hash == s2.byte_hash) {
      return 1.0;
    }

    const auto max_size = std::max({size_t{1}, s1.byte_size, s2.byte_size});
    const auto min_size = std::min(s1.byte_size, s2.byte_size);
    const auto max_instructions = std::max({size_t{1}, s1.instruction_count, s2.instruction_count});
    const auto min_instructions = std::min(s1.instruction_count, s2.instruction_count);
    return std::min(
      static_cast<double>(min_size) / static_cast<double>(max_size),
      static_cast<double>(min_instructions) / static_cast<double>(max_instructions)
    );
  }

  double total_similarity = 0.0;

  for (size_t i = 0; i < std::min(s1.basic_blocks.size(), s2.basic_blocks.size()); i++) {
    const auto& bb1 = s1.basic_blocks[i];
    const auto& bb2 = s2.basic_blocks[i];

    auto distance = subroutine_analyzer::levenshtein_distance(bb1.instructions, bb2.instructions);

    if (bb1.instructions.empty() && bb2.instructions.empty()) {
      total_similarity += 1.0;
      continue;
    }

    double block_similarity = 1.0 - static_cast<double>(distance) /
                                      (std::max({size_t{1}, bb1.instructions.size(), bb2.instructions.size()}) * 100.0);

    const subroutine_analyzer::basic_block* matched_bb2 = &bb2;

    if (block_similarity < 0.3) {
      double best_similarity = block_similarity;
      for (const auto& other_bb : s2.basic_blocks) {
        auto curr_distance = subroutine_analyzer::levenshtein_distance(bb1.instructions, other_bb.instructions);
        double curr_similarity =
          1.0 - static_cast<double>(curr_distance) /
                  (std::max({size_t{1}, bb1.instructions.size(), other_bb.instructions.size()}) * 100.0);

        if (curr_similarity > best_similarity) {
          best_similarity = curr_similarity;
          matched_bb2 = &other_bb;
        }
      }
      block_similarity = best_similarity;
    }

    total_similarity += std::max(0.0, block_similarity);

    if (block_similarity > 0.5 && block_similarity < 1.0) {
      std::string diff_detail = std::format(
        "Block at 0x{:x} -> 0x{:x} ({:.1f}% similar):\n", bb1.start_address, matched_bb2->start_address,
        block_similarity * 100
      );

      auto unified_diff = get_instruction_differences(bb1.instructions, matched_bb2->instructions);
      for (const auto& [op, instr] : unified_diff) {
        diff_detail += std::format("{} {}\n", op, instr);
      }

      diff_details.emplace_back(std::move(diff_detail));
    }
  }

  size_t max_blocks = std::max({size_t{1}, s1.basic_blocks.size(), s2.basic_blocks.size()});
  return total_similarity / static_cast<double>(max_blocks);
}

auto binary_differ::get_instruction_differences(
  const std::vector<std::string>& seq1, const std::vector<std::string>& seq2
) -> std::vector<std::pair<char, std::string>> {
  std::vector<std::pair<char, std::string>> diff;
  auto lcs = get_lcs(seq1, seq2);

  size_t i = 0;
  size_t j = 0;
  size_t k = 0;

  while (k < lcs.size()) {
    while (i < seq1.size() && seq1[i] != lcs[k]) {
      diff.emplace_back('-', seq1[i]);
      i++;
    }

    while (j < seq2.size() && seq2[j] != lcs[k]) {
      diff.emplace_back('+', seq2[j]);
      j++;
    }

    diff.emplace_back('=', lcs[k]);
    i++;
    j++;
    k++;
  }

  while (i < seq1.size()) {
    diff.emplace_back('-', seq1[i]);
    i++;
  }
  while (j < seq2.size()) {
    diff.emplace_back('+', seq2[j]);
    j++;
  }

  return diff;
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
  size_t i = m;
  size_t j = n;
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
  std::unordered_map<
    subroutine_match_key, std::vector<const subroutine_analyzer::subroutine*>, subroutine_match_key_hash>
    primary_map;
  for (const auto& sub : primary_subroutines) {
    primary_map[make_match_key(sub)].push_back(&sub);
  }

  std::unordered_map<
    subroutine_match_key, std::vector<const subroutine_analyzer::subroutine*>, subroutine_match_key_hash>
    secondary_map;
  for (const auto& sub : secondary_subroutines) {
    secondary_map[make_match_key(sub)].push_back(&sub);
  }

  using match_candidate = std::tuple<
    double, const subroutine_analyzer::subroutine*, const subroutine_analyzer::subroutine*, std::vector<std::string>>;
  std::vector<match_candidate> similarities;

  auto sort_candidates = [](const match_candidate& a, const match_candidate& b) {
    double sim_a = std::get<0>(a);
    double sim_b = std::get<0>(b);
    if (std::abs(sim_a - sim_b) > 0.0001) {
      return sim_a > sim_b;
    }

    auto addr_p_a = std::get<1>(a)->start_address;
    auto addr_s_a = std::get<2>(a)->start_address;
    auto addr_p_b = std::get<1>(b)->start_address;
    auto addr_s_b = std::get<2>(b)->start_address;

    bool a_exact = (addr_p_a == addr_s_a);
    bool b_exact = (addr_p_b == addr_s_b);
    if (a_exact != b_exact) {
      return a_exact;
    }

    auto diff_a = addr_p_a > addr_s_a ? addr_p_a - addr_s_a : addr_s_a - addr_p_a;
    auto diff_b = addr_p_b > addr_s_b ? addr_p_b - addr_s_b : addr_s_b - addr_p_b;
    if (diff_a != diff_b) {
      return diff_a < diff_b;
    }

    if (addr_p_a != addr_p_b) {
      return addr_p_a < addr_p_b;
    }
    return addr_s_a < addr_s_b;
  };

  std::ranges::sort(similarities, sort_candidates);

  std::vector<std::pair<subroutine_analyzer::subroutine, subroutine_analyzer::subroutine>> matches;
  std::set<uint64_t> matched_primary_addrs;
  std::set<uint64_t> matched_secondary_addrs;

  auto resolve_matches = [&](const std::vector<match_candidate>& cands) {
    for (const auto& [similarity, primary_sub, secondary_sub, details] : cands) {
      if (
        matched_primary_addrs.contains(primary_sub->start_address) ||
        matched_secondary_addrs.contains(secondary_sub->start_address)
      ) {
        continue;
      }
      auto primary_copy = *primary_sub;
      primary_copy.similarity_score = similarity;
      primary_copy.diff_details = details;
      matches.emplace_back(std::move(primary_copy), *secondary_sub);
      matched_primary_addrs.insert(primary_sub->start_address);
      matched_secondary_addrs.insert(secondary_sub->start_address);
    }
  };

  std::vector<match_candidate> exact_matches;
  exact_matches.reserve(primary_subroutines.size());
  // pair equal fingerprints by address order to avoid duplicate bucket scans
  for (auto& [key, primary_bucket] : primary_map) {
    auto secondary_it = secondary_map.find(key);
    if (secondary_it == secondary_map.end()) {
      continue;
    }

    auto& secondary_bucket = secondary_it->second;
    std::ranges::sort(primary_bucket, [](const auto* lhs, const auto* rhs) {
      return lhs->start_address < rhs->start_address;
    });
    std::ranges::sort(secondary_bucket, [](const auto* lhs, const auto* rhs) {
      return lhs->start_address < rhs->start_address;
    });

    const auto match_count = std::min(primary_bucket.size(), secondary_bucket.size());
    for (size_t i = 0; i < match_count; ++i) {
      const auto* primary_sub = primary_bucket[i];
      const auto* secondary_sub = secondary_bucket[i];
      if (!options_.decode_instructions) {
        exact_matches.emplace_back(1.0, primary_sub, secondary_sub, std::vector<std::string>{});
        continue;
      }

      std::vector<std::string> diff_details;
      const auto similarity = get_subroutine_similarity(*primary_sub, *secondary_sub, diff_details);
      if (similarity > options_.minimum_similarity) {
        exact_matches.emplace_back(similarity, primary_sub, secondary_sub, std::move(diff_details));
      }
    }
  }

  std::ranges::sort(exact_matches, sort_candidates);
  resolve_matches(exact_matches);

  std::map<int64_t, size_t> delta_counts;
  for (const auto& [primary_sub, secondary_sub] : matches) {
    ++delta_counts[address_delta(primary_sub.start_address, secondary_sub.start_address)];
  }

  std::vector<std::pair<int64_t, size_t>> ranked_deltas(delta_counts.begin(), delta_counts.end());
  std::ranges::sort(ranked_deltas, [](const auto& lhs, const auto& rhs) {
    if (lhs.second != rhs.second) {
      return lhs.second > rhs.second;
    }
    return std::abs(lhs.first) < std::abs(rhs.first);
  });

  std::vector<int64_t> address_deltas{0};
  // common deltas catch small global shifts after exact matches anchor the map
  for (const auto& [delta, count] : ranked_deltas) {
    if (count < 16) {
      continue;
    }
    if (!std::ranges::contains(address_deltas, delta)) {
      address_deltas.push_back(delta);
    }
    if (address_deltas.size() == 4) {
      break;
    }
  }

  std::unordered_map<uint64_t, const subroutine_analyzer::subroutine*> secondary_by_address;
  for (const auto& sub : secondary_subroutines) {
    secondary_by_address.emplace(sub.start_address, &sub);
  }

  std::vector<match_candidate> address_matches;
  for (const auto& primary_sub : primary_subroutines) {
    if (matched_primary_addrs.contains(primary_sub.start_address)) {
      continue;
    }

    for (const auto delta : address_deltas) {
      const auto secondary_address = add_delta(primary_sub.start_address, delta);
      if (!secondary_address) {
        continue;
      }

      auto secondary_it = secondary_by_address.find(*secondary_address);
      if (
        secondary_it == secondary_by_address.end() ||
        matched_secondary_addrs.contains(secondary_it->second->start_address)
      ) {
        continue;
      }

      std::vector<std::string> diff_details;
      const auto similarity = get_subroutine_similarity(primary_sub, *secondary_it->second, diff_details);
      address_matches.emplace_back(similarity, &primary_sub, secondary_it->second, std::move(diff_details));
    }
  }

  std::ranges::sort(address_matches, sort_candidates);
  resolve_matches(address_matches);

  if (!options_.decode_instructions) {
    return matches;
  }

  std::vector<const subroutine_analyzer::subroutine*> unmatched_primary;
  for (const auto& sub : primary_subroutines) {
    if (!matched_primary_addrs.contains(sub.start_address)) {
      unmatched_primary.push_back(&sub);
    }
  }

  std::vector<const subroutine_analyzer::subroutine*> unmatched_secondary;
  for (const auto& sub : secondary_subroutines) {
    if (!matched_secondary_addrs.contains(sub.start_address)) {
      unmatched_secondary.push_back(&sub);
    }
  }

  if (!unmatched_primary.empty() && !unmatched_secondary.empty()) {
    similarities.clear();

    const auto pair_count = unmatched_primary.size() > std::numeric_limits<size_t>::max() / unmatched_secondary.size()
                              ? std::numeric_limits<size_t>::max()
                              : unmatched_primary.size() * unmatched_secondary.size();
    size_t candidate_count = 0;

    auto append_candidate =
      [&](const subroutine_analyzer::subroutine* p_sub, const subroutine_analyzer::subroutine* s_sub) {
        if (candidate_count >= options_.max_pairwise_candidates) {
          return;
        }

        ++candidate_count;
        std::vector<std::string> diff_details;
        double similarity = get_subroutine_similarity(*p_sub, *s_sub, diff_details);
        if (similarity > options_.fallback_similarity) {
          similarities.emplace_back(similarity, p_sub, s_sub, std::move(diff_details));
        }
      };

    if (pair_count <= options_.max_pairwise_candidates) {
      for (const auto* p_sub : unmatched_primary) {
        for (const auto* s_sub : unmatched_secondary) {
          append_candidate(p_sub, s_sub);
        }
      }
    } else {
      auto secondary_by_start = unmatched_secondary;
      std::ranges::sort(secondary_by_start, [](const auto* lhs, const auto* rhs) {
        return lhs->start_address < rhs->start_address;
      });

      for (const auto* p_sub : unmatched_primary) {
        const auto min_address = p_sub->start_address - std::min(p_sub->start_address, options_.address_match_radius);
        const auto max_address =
          p_sub->start_address > std::numeric_limits<uint64_t>::max() - options_.address_match_radius
            ? std::numeric_limits<uint64_t>::max()
            : p_sub->start_address + options_.address_match_radius;
        auto first = std::lower_bound(
          secondary_by_start.begin(), secondary_by_start.end(), min_address, [](const auto* lhs, uint64_t rhs) {
            return lhs->start_address < rhs;
          }
        );

        for (auto it = first; it != secondary_by_start.end(); ++it) {
          if ((*it)->start_address > max_address) {
            break;
          }
          append_candidate(p_sub, *it);
        }
      }

      for (const auto* p_sub : unmatched_primary) {
        if (candidate_count >= options_.max_pairwise_candidates) {
          break;
        }
        for (const auto* s_sub : unmatched_secondary) {
          if (candidate_count >= options_.max_pairwise_candidates) {
            break;
          }
          if (address_distance(p_sub->start_address, s_sub->start_address) <= options_.address_match_radius) {
            continue;
          }
          append_candidate(p_sub, s_sub);
        }
      }

      skipped_pairwise_candidates_ += pair_count > candidate_count ? pair_count - candidate_count : 0;
    }

    std::ranges::sort(similarities, sort_candidates);
    resolve_matches(similarities);
  }

  return matches;
}
