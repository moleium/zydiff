#include "differ.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <future>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stop_token>
#include <thread>
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

  struct match_key {
    fingerprint code_fingerprint{};
    size_t byte_size{};
    size_t instruction_count{};

    [[nodiscard]] auto operator==(const match_key&) const -> bool = default;
  };

  struct match_key_hash {
    [[nodiscard]] auto operator()(const match_key& key) const -> size_t {
      auto hash = static_cast<uint64_t>(key.code_fingerprint);
      hash ^= static_cast<uint64_t>(key.byte_size) + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
      hash ^= static_cast<uint64_t>(key.instruction_count) + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
      return static_cast<size_t>(hash);
    }
  };

  [[nodiscard]] auto make_key(const subroutine_analyzer::subroutine& sub) -> match_key {
    return match_key{
      .code_fingerprint = sub.fingerprint,
      .byte_size = sub.byte_size,
      .instruction_count = sub.instruction_count,
    };
  }

  double block_upper_bound(
    const subroutine_analyzer::basic_block& primary, const subroutine_analyzer::basic_block& secondary
  ) {
    const auto maximum = std::max({size_t{1}, primary.instructions.size(), secondary.instructions.size()});
    const auto minimum = std::min(primary.instructions.size(), secondary.instructions.size());
    return static_cast<double>(minimum) / static_cast<double>(maximum);
  }

  std::string normalize_instruction(std::string_view instruction) {
    std::string result;
    result.reserve(instruction.size());

    for (size_t i = 0; i < instruction.size(); ++i) {
      if (instruction.substr(i).starts_with("0x")) {
        result += "0x?";
        i += 2;
        while (i < instruction.size() && std::isxdigit(static_cast<unsigned char>(instruction[i]))) {
          ++i;
        }
        --i;
      } else {
        result += instruction[i];
      }
    }
    return result;
  }

  std::optional<double>
  aligned_similarity(const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary) {
    if (primary.basic_blocks.size() != secondary.basic_blocks.size()) {
      return std::nullopt;
    }

    double total_similarity = 0.0;
    for (size_t i = 0; i < primary.basic_blocks.size(); ++i) {
      const auto& primary_block = primary.basic_blocks[i];
      const auto& secondary_block = secondary.basic_blocks[i];
      if (
        primary_block.instructions.size() != secondary_block.instructions.size() ||
        primary_block.successors.size() != secondary_block.successors.size()
      ) {
        return std::nullopt;
      }
      if (primary_block.instructions.empty()) {
        total_similarity += 1.0;
        continue;
      }

      size_t normalized_changes = 0;
      for (size_t j = 0; j < primary_block.instructions.size(); ++j) {
        if (primary_block.instructions[j] == secondary_block.instructions[j]) {
          continue;
        }
        if (
          normalize_instruction(primary_block.instructions[j]) != normalize_instruction(secondary_block.instructions[j])
        ) {
          return std::nullopt;
        }
        ++normalized_changes;
      }

      // cant improve a substitution cost of 200 or less
      if (normalized_changes > 20) {
        return std::nullopt;
      }

      total_similarity +=
        1.0 - static_cast<double>(normalized_changes) / (static_cast<double>(primary_block.instructions.size()) * 10.0);
    }

    const auto block_count = std::max(size_t{1}, primary.basic_blocks.size());
    return total_similarity / static_cast<double>(block_count);
  }

  double
  quick_similarity(const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary) {
    const auto compared_blocks = std::min(primary.basic_blocks.size(), secondary.basic_blocks.size());
    const auto maximum_blocks = std::max({size_t{1}, primary.basic_blocks.size(), secondary.basic_blocks.size()});
    double total_similarity = 0.0;

    for (size_t i = 0; i < compared_blocks; ++i) {
      const auto& primary_block = primary.basic_blocks[i];
      const auto& secondary_block = secondary.basic_blocks[i];
      const auto compared_instructions =
        std::min(primary_block.instructions.size(), secondary_block.instructions.size());
      const auto maximum_instructions =
        std::max({size_t{1}, primary_block.instructions.size(), secondary_block.instructions.size()});
      double block_similarity = 0.0;

      for (size_t j = 0; j < compared_instructions; ++j) {
        if (primary_block.instructions[j] == secondary_block.instructions[j]) {
          block_similarity += 1.0;
        } else if (
          normalize_instruction(primary_block.instructions[j]) == normalize_instruction(secondary_block.instructions[j])
        ) {
          block_similarity += 0.9;
        }
      }
      total_similarity += block_similarity / static_cast<double>(maximum_instructions);
    }

    return total_similarity / static_cast<double>(maximum_blocks);
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
  skipped_candidates_ = 0;

  auto primary_text = primary_->get_text_section();
  auto secondary_text = secondary_->get_text_section();

  if (!primary_text || !secondary_text) {
    std::println(stderr, "error: failed to get text sections");
    return result;
  }

  const auto analysis_workers = std::max(1u, std::thread::hardware_concurrency() / 2);
  std::stop_source analysis_stop;
  const auto analysis_token = analysis_stop.get_token();

  auto primary_future = std::async(std::launch::async, [&, analysis_token] {
    try {
      subroutine_analyzer analyzer(
        primary_text->data.data(), primary_text->size, primary_->get_image_base() + primary_text->virtual_address,
        primary_->get_function_starts(), options_.decode_instructions, analysis_workers, analysis_token
      );
      return analyzer.get_subroutines();
    } catch (...) {
      analysis_stop.request_stop();
      throw;
    }
  });

  std::vector<subroutine_analyzer::subroutine> secondary_subroutines;
  try {
    subroutine_analyzer secondary_analyzer(
      secondary_text->data.data(), secondary_text->size, secondary_->get_image_base() + secondary_text->virtual_address,
      secondary_->get_function_starts(), options_.decode_instructions, analysis_workers, analysis_token
    );
    secondary_subroutines = secondary_analyzer.get_subroutines();
  } catch (...) {
    const bool primary_failed = analysis_stop.stop_requested();
    const auto failure = std::current_exception();
    analysis_stop.request_stop();
    if (primary_failed) {
      primary_future.get();
    }
    try {
      primary_future.get();
    } catch (...) {
    }
    std::rethrow_exception(failure);
  }
  auto primary_subroutines = primary_future.get();
  result.primary_count = primary_subroutines.size();
  result.secondary_count = secondary_subroutines.size();

  auto matches = match_subroutines(primary_subroutines, secondary_subroutines);
  result.skipped_candidates = skipped_candidates_;

  std::vector<bool> matched_primary(primary_subroutines.size());
  std::vector<bool> matched_secondary(secondary_subroutines.size());
  result.matches.reserve(matches.size());
  for (auto& match : matches) {
    auto primary = std::move(primary_subroutines[match.primary_index]);
    primary.similarity_score = match.similarity;
    primary.diff_details = std::move(match.diff_details);
    result.matches.emplace_back(std::move(primary), std::move(secondary_subroutines[match.secondary_index]));
    matched_primary[match.primary_index] = true;
    matched_secondary[match.secondary_index] = true;
  }

  result.unmatched_primary.reserve(primary_subroutines.size() - matches.size());
  for (size_t i = 0; i < primary_subroutines.size(); ++i) {
    if (!matched_primary[i]) {
      result.unmatched_primary.push_back(std::move(primary_subroutines[i]));
    }
  }

  result.unmatched_secondary.reserve(secondary_subroutines.size() - matches.size());
  for (size_t i = 0; i < secondary_subroutines.size(); ++i) {
    if (!matched_secondary[i]) {
      result.unmatched_secondary.push_back(std::move(secondary_subroutines[i]));
    }
  }

  return result;
}

double binary_differ::score_subroutines(
  const subroutine_analyzer::subroutine& s1, const subroutine_analyzer::subroutine& s2,
  std::vector<std::string>* diff_details
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

    const auto maximum_instructions = std::max({size_t{1}, bb1.instructions.size(), bb2.instructions.size()});
    double block_similarity = 1.0 - static_cast<double>(distance) / (static_cast<double>(maximum_instructions) * 100.0);

    const subroutine_analyzer::basic_block* matched_bb2 = &bb2;

    if (block_similarity < 0.3) {
      double best_similarity = block_similarity;
      for (const auto& other_bb : s2.basic_blocks) {
        if (&other_bb == &bb2) {
          continue;
        }
        if (block_upper_bound(bb1, other_bb) <= best_similarity) {
          continue;
        }
        auto curr_distance = subroutine_analyzer::levenshtein_distance(bb1.instructions, other_bb.instructions);
        const auto maximum_instructions = std::max({size_t{1}, bb1.instructions.size(), other_bb.instructions.size()});
        double curr_similarity =
          1.0 - static_cast<double>(curr_distance) / (static_cast<double>(maximum_instructions) * 100.0);

        if (curr_similarity > best_similarity) {
          best_similarity = curr_similarity;
          matched_bb2 = &other_bb;
        }
      }
      block_similarity = best_similarity;
    }

    total_similarity += std::max(0.0, block_similarity);

    if (diff_details != nullptr && block_similarity > 0.5 && block_similarity < 1.0) {
      std::string diff_detail = std::format(
        "Block at 0x{:x} -> 0x{:x} ({:.1f}% similar):\n", bb1.start_address, matched_bb2->start_address,
        block_similarity * 100
      );

      auto unified_diff = diff_instructions(bb1.instructions, matched_bb2->instructions);
      for (const auto& [op, instr] : unified_diff) {
        diff_detail += std::format("{} {}\n", op, instr);
      }

      diff_details->emplace_back(std::move(diff_detail));
    }
  }

  size_t max_blocks = std::max({size_t{1}, s1.basic_blocks.size(), s2.basic_blocks.size()});
  return total_similarity / static_cast<double>(max_blocks);
}

auto binary_differ::diff_instructions(const std::vector<std::string>& seq1, const std::vector<std::string>& seq2)
  -> std::vector<std::pair<char, std::string>> {
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

std::vector<binary_differ::subroutine_match> binary_differ::match_subroutines(
  const std::vector<subroutine_analyzer::subroutine>& primary_subroutines,
  const std::vector<subroutine_analyzer::subroutine>& secondary_subroutines
) {
  std::unordered_map<match_key, std::vector<const subroutine_analyzer::subroutine*>, match_key_hash> primary_map;
  for (const auto& sub : primary_subroutines) {
    primary_map[make_key(sub)].push_back(&sub);
  }

  std::unordered_map<match_key, std::vector<const subroutine_analyzer::subroutine*>, match_key_hash> secondary_map;
  for (const auto& sub : secondary_subroutines) {
    secondary_map[make_key(sub)].push_back(&sub);
  }

  using match_candidate = std::tuple<
    double, const subroutine_analyzer::subroutine*, const subroutine_analyzer::subroutine*, std::vector<std::string>>;
  using candidate_pair = std::pair<const subroutine_analyzer::subroutine*, const subroutine_analyzer::subroutine*>;
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

  std::vector<subroutine_match> matches;
  matches.reserve(std::min(primary_subroutines.size(), secondary_subroutines.size()));
  std::set<uint64_t> matched_primary_addrs;
  std::set<uint64_t> matched_secondary_addrs;

  auto resolve_matches = [&](std::vector<match_candidate>& cands) {
    for (auto& [similarity, primary_sub, secondary_sub, details] : cands) {
      if (
        matched_primary_addrs.contains(primary_sub->start_address) ||
        matched_secondary_addrs.contains(secondary_sub->start_address)
      ) {
        continue;
      }
      matches.push_back({
        .primary_index = static_cast<size_t>(primary_sub - primary_subroutines.data()),
        .secondary_index = static_cast<size_t>(secondary_sub - secondary_subroutines.data()),
        .similarity = similarity,
        .diff_details = std::move(details),
      });
      matched_primary_addrs.insert(primary_sub->start_address);
      matched_secondary_addrs.insert(secondary_sub->start_address);
    }
  };

  std::vector<candidate_pair> exact_pairs;
  exact_pairs.reserve(primary_subroutines.size());
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
      exact_pairs.emplace_back(primary_bucket[i], secondary_bucket[i]);
    }
  }

  const auto exact_workers = std::min<size_t>(std::max(1u, std::thread::hardware_concurrency()), exact_pairs.size());
  std::atomic_size_t exact_index{0};
  std::stop_source exact_stop;
  std::exception_ptr exact_failure;
  std::mutex exact_mutex;
  std::vector<std::vector<match_candidate>> exact_batches(exact_workers);
  {
    std::vector<std::jthread> workers;
    workers.reserve(exact_workers);
    for (size_t thread_index = 0; thread_index < exact_workers; ++thread_index) {
      workers.emplace_back([&, thread_index] {
        try {
          auto& output = exact_batches[thread_index];
          while (!exact_stop.stop_requested()) {
            const auto index = exact_index.fetch_add(1, std::memory_order_relaxed);
            if (index >= exact_pairs.size()) {
              break;
            }
            const auto [primary_sub, secondary_sub] = exact_pairs[index];
            if (!options_.decode_instructions) {
              output.emplace_back(1.0, primary_sub, secondary_sub, std::vector<std::string>{});
              continue;
            }

            const auto aligned_score = aligned_similarity(*primary_sub, *secondary_sub);
            const auto similarity = aligned_score ? *aligned_score : score_subroutines(*primary_sub, *secondary_sub);
            if (similarity > options_.match_threshold) {
              output.emplace_back(similarity, primary_sub, secondary_sub, std::vector<std::string>{});
            }
          }
        } catch (...) {
          exact_stop.request_stop();
          const std::scoped_lock lock(exact_mutex);
          if (!exact_failure) {
            exact_failure = std::current_exception();
          }
        }
      });
    }
  }
  if (exact_failure) {
    std::rethrow_exception(exact_failure);
  }

  std::vector<match_candidate> exact_matches;
  exact_matches.reserve(exact_pairs.size());
  for (auto& batch : exact_batches) {
    exact_matches.insert(
      exact_matches.end(), std::make_move_iterator(batch.begin()), std::make_move_iterator(batch.end())
    );
  }

  std::ranges::sort(exact_matches, sort_candidates);
  resolve_matches(exact_matches);

  std::map<int64_t, size_t> delta_counts;
  for (const auto& match : matches) {
    ++delta_counts[address_delta(
      primary_subroutines[match.primary_index].start_address, secondary_subroutines[match.secondary_index].start_address
    )];
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

  std::vector<candidate_pair> address_pairs;
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

      address_pairs.emplace_back(&primary_sub, secondary_it->second);
    }
  }

  const auto address_workers =
    std::min<size_t>(std::max(1u, std::thread::hardware_concurrency()), address_pairs.size());
  std::atomic_size_t address_index{0};
  std::stop_source address_stop;
  std::exception_ptr address_failure;
  std::mutex address_mutex;
  std::vector<std::vector<match_candidate>> address_batches(address_workers);
  {
    std::vector<std::jthread> workers;
    workers.reserve(address_workers);
    for (size_t thread_index = 0; thread_index < address_workers; ++thread_index) {
      workers.emplace_back([&, thread_index] {
        try {
          auto& output = address_batches[thread_index];
          while (!address_stop.stop_requested()) {
            const auto index = address_index.fetch_add(1, std::memory_order_relaxed);
            if (index >= address_pairs.size()) {
              break;
            }
            const auto [primary_sub, secondary_sub] = address_pairs[index];
            output.emplace_back(
              score_subroutines(*primary_sub, *secondary_sub), primary_sub, secondary_sub, std::vector<std::string>{}
            );
          }
        } catch (...) {
          address_stop.request_stop();
          const std::scoped_lock lock(address_mutex);
          if (!address_failure) {
            address_failure = std::current_exception();
          }
        }
      });
    }
  }
  if (address_failure) {
    std::rethrow_exception(address_failure);
  }

  std::vector<match_candidate> address_matches;
  address_matches.reserve(address_pairs.size());
  for (auto& batch : address_batches) {
    address_matches.insert(
      address_matches.end(), std::make_move_iterator(batch.begin()), std::make_move_iterator(batch.end())
    );
  }

  std::ranges::sort(address_matches, sort_candidates);
  resolve_matches(address_matches);

  if (!options_.decode_instructions) {
    return matches;
  }

  if (options_.fallback_limit == 0) {
    if (options_.generate_details) {
      for (auto& match : matches) {
        if (match.similarity < 1.0) {
          score_subroutines(
            primary_subroutines[match.primary_index], secondary_subroutines[match.secondary_index], &match.diff_details
          );
        }
      }
    }
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
    const bool limited_search = pair_count > options_.pair_limit;
    std::vector<candidate_pair> candidate_pairs;
    candidate_pairs.reserve(std::min(pair_count, options_.pair_limit));

    struct ranked_candidate {
      const subroutine_analyzer::subroutine* secondary;
      double shape_ratio;
      double instruction_ratio;
      double byte_ratio;
      bool nearby;
      uint64_t distance;
    };
    auto compare_rank = [](const ranked_candidate& lhs, const ranked_candidate& rhs) {
      if (lhs.shape_ratio != rhs.shape_ratio) {
        return lhs.shape_ratio > rhs.shape_ratio;
      }
      if (lhs.instruction_ratio != rhs.instruction_ratio) {
        return lhs.instruction_ratio > rhs.instruction_ratio;
      }
      if (lhs.byte_ratio != rhs.byte_ratio) {
        return lhs.byte_ratio > rhs.byte_ratio;
      }
      if (lhs.nearby != rhs.nearby) {
        return lhs.nearby;
      }
      if (lhs.distance != rhs.distance) {
        return lhs.distance < rhs.distance;
      }
      return lhs.secondary->start_address < rhs.secondary->start_address;
    };

    if (!limited_search) {
      for (const auto* primary_sub : unmatched_primary) {
        for (const auto* secondary_sub : unmatched_secondary) {
          candidate_pairs.emplace_back(primary_sub, secondary_sub);
        }
      }
    } else {
      for (const auto* primary_sub : unmatched_primary) {
        if (candidate_pairs.size() >= options_.pair_limit) {
          break;
        }

        std::vector<ranked_candidate> ranked_candidates;
        ranked_candidates.reserve(unmatched_secondary.size());
        for (const auto* secondary_sub : unmatched_secondary) {
          const auto block_ratio =
            static_cast<double>(std::min(primary_sub->basic_blocks.size(), secondary_sub->basic_blocks.size())) /
            static_cast<double>(
              std::max({size_t{1}, primary_sub->basic_blocks.size(), secondary_sub->basic_blocks.size()})
            );
          const auto instruction_ratio =
            static_cast<double>(std::min(primary_sub->instruction_count, secondary_sub->instruction_count)) /
            static_cast<double>(
              std::max({size_t{1}, primary_sub->instruction_count, secondary_sub->instruction_count})
            );
          const auto byte_ratio =
            static_cast<double>(std::min(primary_sub->byte_size, secondary_sub->byte_size)) /
            static_cast<double>(std::max({size_t{1}, primary_sub->byte_size, secondary_sub->byte_size}));
          const auto distance = address_distance(primary_sub->start_address, secondary_sub->start_address);
          ranked_candidates.push_back({
            .secondary = secondary_sub,
            .shape_ratio = std::min({block_ratio, instruction_ratio, byte_ratio}),
            .instruction_ratio = instruction_ratio,
            .byte_ratio = byte_ratio,
            .nearby = distance <= options_.address_radius,
            .distance = distance,
          });
        }

        const auto remaining_limit = options_.pair_limit - candidate_pairs.size();
        const auto candidate_limit = std::min({options_.fallback_limit, ranked_candidates.size(), remaining_limit});
        std::ranges::partial_sort(
          ranked_candidates, ranked_candidates.begin() + static_cast<std::ptrdiff_t>(candidate_limit), compare_rank
        );
        for (size_t i = 0; i < candidate_limit; ++i) {
          candidate_pairs.emplace_back(primary_sub, ranked_candidates[i].secondary);
        }
      }
    }

    skipped_candidates_ += pair_count > candidate_pairs.size() ? pair_count - candidate_pairs.size() : 0;

    const auto thread_count =
      std::min<size_t>(std::max(1u, std::thread::hardware_concurrency()), candidate_pairs.size());
    std::atomic_size_t next_candidate{0};
    std::atomic_size_t skipped_scores{0};
    std::stop_source scoring_stop;
    std::exception_ptr scoring_failure;
    std::mutex failure_mutex;
    std::vector<std::vector<match_candidate>> scored_candidates(thread_count);
    {
      std::vector<std::jthread> workers;
      workers.reserve(thread_count);
      for (size_t thread_index = 0; thread_index < thread_count; ++thread_index) {
        workers.emplace_back([&, thread_index] {
          try {
            auto& output = scored_candidates[thread_index];
            while (!scoring_stop.stop_requested()) {
              const auto index = next_candidate.fetch_add(1, std::memory_order_relaxed);
              if (index >= candidate_pairs.size()) {
                break;
              }

              const auto [primary_sub, secondary_sub] = candidate_pairs[index];
              if (limited_search) {
                const auto quick_score = quick_similarity(*primary_sub, *secondary_sub);
                const auto threshold = std::max(options_.fallback_threshold, options_.quick_threshold);
                if (quick_score <= threshold) {
                  skipped_scores.fetch_add(1, std::memory_order_relaxed);
                  continue;
                }
              }
              const auto similarity = score_subroutines(*primary_sub, *secondary_sub);
              if (similarity > options_.fallback_threshold) {
                output.emplace_back(similarity, primary_sub, secondary_sub, std::vector<std::string>{});
              }
            }
          } catch (...) {
            scoring_stop.request_stop();
            const std::scoped_lock lock(failure_mutex);
            if (!scoring_failure) {
              scoring_failure = std::current_exception();
            }
          }
        });
      }
    }
    if (scoring_failure) {
      std::rethrow_exception(scoring_failure);
    }
    skipped_candidates_ += skipped_scores.load(std::memory_order_relaxed);

    size_t scored_count = 0;
    for (const auto& candidates : scored_candidates) {
      scored_count += candidates.size();
    }
    similarities.reserve(scored_count);
    for (auto& candidates : scored_candidates) {
      similarities.insert(
        similarities.end(), std::make_move_iterator(candidates.begin()), std::make_move_iterator(candidates.end())
      );
    }

    std::ranges::sort(similarities, sort_candidates);
    resolve_matches(similarities);
  }

  if (!options_.generate_details) {
    return matches;
  }

  for (auto& match : matches) {
    if (match.similarity >= 1.0) {
      continue;
    }
    score_subroutines(
      primary_subroutines[match.primary_index], secondary_subroutines[match.secondary_index], &match.diff_details
    );
  }

  return matches;
}
