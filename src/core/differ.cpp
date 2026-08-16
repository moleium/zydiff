#include "differ.h"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <future>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <unordered_map>
#include <unordered_set>
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
    return delta > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ? -std::numeric_limits<int64_t>::max()
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

  std::vector<subroutine_analyzer::address_range> get_ranges(const binary_parser& parser) {
    std::vector<subroutine_analyzer::address_range> ranges;
    for (const auto& section : parser.get_sections()) {
      if (section.mapped_size == 0 || section.virtual_address == 0) {
        continue;
      }
      const auto start = parser.get_image_base() + section.virtual_address;
      const auto end = start > std::numeric_limits<uint64_t>::max() - section.mapped_size
                         ? std::numeric_limits<uint64_t>::max()
                         : start + section.mapped_size;
      ranges.push_back({.start = start, .end = end});
    }
    return ranges;
  }

  struct match_key {
    fingerprint code_fingerprint{};
    size_t instruction_count{};

    [[nodiscard]] auto operator==(const match_key&) const -> bool = default;
  };

  struct match_key_hash {
    [[nodiscard]] auto operator()(const match_key& key) const -> size_t {
      auto hash = static_cast<uint64_t>(key.code_fingerprint);
      hash ^= static_cast<uint64_t>(key.instruction_count) + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
      return static_cast<size_t>(hash);
    }
  };

  [[nodiscard]] auto make_key(const subroutine_analyzer::subroutine& sub) -> match_key {
    return match_key{
      .code_fingerprint = sub.fingerprint,
      .instruction_count = sub.instruction_count,
    };
  }

  double block_upper_bound(
    const subroutine_analyzer::basic_block& primary, const subroutine_analyzer::basic_block& secondary
  ) {
    const auto maximum = std::max({size_t{1}, primary.instruction_keys.size(), secondary.instruction_keys.size()});
    const auto minimum = std::min(primary.instruction_keys.size(), secondary.instruction_keys.size());
    return static_cast<double>(minimum) / static_cast<double>(maximum);
  }

  size_t
  block_distance(const subroutine_analyzer::basic_block& primary, const subroutine_analyzer::basic_block& secondary) {
    if (
      primary.match_keys == secondary.match_keys && primary.instruction_keys.size() == secondary.instruction_keys.size()
    ) {
      size_t changes = 0;
      for (size_t i = 0; i < primary.instruction_keys.size(); ++i) {
        changes += primary.instruction_keys[i] != secondary.instruction_keys[i];
      }
      return changes * 10;
    }
    return subroutine_analyzer::levenshtein_distance(primary.instruction_keys, secondary.instruction_keys);
  }

  bool blocks_equal(const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary) {
    if (primary.basic_blocks.size() != secondary.basic_blocks.size()) {
      return false;
    }

    for (size_t i = 0; i < primary.basic_blocks.size(); ++i) {
      const auto& primary_block = primary.basic_blocks[i];
      const auto& secondary_block = secondary.basic_blocks[i];
      if (
        primary_block.instruction_keys != secondary_block.instruction_keys ||
        primary_block.successor_keys != secondary_block.successor_keys
      ) {
        return false;
      }
    }
    return true;
  }

  std::vector<size_t> make_block_map(size_t primary_count, std::span<const binary_differ::block_match> matches) {
    std::vector<size_t> block_map(primary_count, primary_count);
    for (const auto& match : matches) {
      block_map[match.primary_index] = match.secondary_index;
    }
    return block_map;
  }

  bool has_same_flow(
    const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary,
    std::span<const binary_differ::block_match> matches, std::span<const size_t> block_map
  ) {
    for (const auto& match : matches) {
      std::vector<size_t> primary_targets;
      for (const auto successor : primary.basic_blocks[match.primary_index].successor_keys) {
        const auto target = static_cast<int64_t>(match.primary_index) + successor;
        if (target < 0 || static_cast<size_t>(target) >= block_map.size()) {
          return false;
        }
        const auto mapped_target = block_map[static_cast<size_t>(target)];
        if (mapped_target >= secondary.basic_blocks.size()) {
          return false;
        }
        primary_targets.push_back(mapped_target);
      }

      std::vector<size_t> secondary_targets;
      for (const auto successor : secondary.basic_blocks[match.secondary_index].successor_keys) {
        const auto target = static_cast<int64_t>(match.secondary_index) + successor;
        if (target < 0 || static_cast<size_t>(target) >= secondary.basic_blocks.size()) {
          return false;
        }
        secondary_targets.push_back(static_cast<size_t>(target));
      }

      std::ranges::sort(primary_targets);
      std::ranges::sort(secondary_targets);
      if (primary_targets != secondary_targets) {
        return false;
      }
    }
    return true;
  }

  binary_differ::change_type classify_change(
    const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary, double similarity
  ) {
    if (similarity >= 1.0) {
      return binary_differ::change_type::unchanged;
    }
    const auto block_matches = binary_differ::match_blocks(primary, secondary);
    if (
      primary.basic_blocks.size() != secondary.basic_blocks.size() ||
      block_matches.size() != primary.basic_blocks.size()
    ) {
      return binary_differ::change_type::instructions_changed;
    }

    bool flow_changed = false;
    bool instructions_changed = false;
    const auto block_map = make_block_map(primary.basic_blocks.size(), block_matches);
    flow_changed = !has_same_flow(primary, secondary, block_matches, block_map);
    for (const auto& match : block_matches) {
      const auto& primary_block = primary.basic_blocks[match.primary_index];
      const auto& secondary_block = secondary.basic_blocks[match.secondary_index];
      instructions_changed |= primary_block.match_keys != secondary_block.match_keys;
    }
    if (flow_changed) {
      return binary_differ::change_type::flow_changed;
    }
    return instructions_changed ? binary_differ::change_type::instructions_changed
                                : binary_differ::change_type::values_changed;
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
    throw std::runtime_error("failed to find text sections");
  }

  const auto analysis_workers = std::max(1u, std::thread::hardware_concurrency() / 2);
  const auto primary_ranges = get_ranges(*primary_);
  const auto secondary_ranges = get_ranges(*secondary_);
  std::stop_source analysis_stop;
  const auto analysis_token = analysis_stop.get_token();

  auto primary_future = std::async(std::launch::async, [&, analysis_token] {
    try {
      subroutine_analyzer analyzer(
        primary_text->data.data(), primary_text->data.size(),
        primary_->get_image_base() + primary_text->virtual_address, primary_->get_function_starts(),
        options_.decode_instructions, analysis_workers, analysis_token, primary_ranges
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
      secondary_text->data.data(), secondary_text->data.size(),
      secondary_->get_image_base() + secondary_text->virtual_address, secondary_->get_function_starts(),
      options_.decode_instructions, analysis_workers, analysis_token, secondary_ranges
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
    const auto change = classify_change(
      primary_subroutines[match.primary_index], secondary_subroutines[match.secondary_index], match.similarity
    );
    auto primary = std::move(primary_subroutines[match.primary_index]);
    result.matches.push_back({
      .primary = std::move(primary),
      .secondary = std::move(secondary_subroutines[match.secondary_index]),
      .change = change,
      .similarity = match.similarity,
    });
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

std::vector<binary_differ::block_match> binary_differ::match_blocks(
  const subroutine_analyzer::subroutine& primary, const subroutine_analyzer::subroutine& secondary
) {
  std::vector<block_match> matches;
  matches.reserve(std::min(primary.basic_blocks.size(), secondary.basic_blocks.size()));
  std::unordered_map<uint64_t, std::vector<const subroutine_analyzer::basic_block*>> secondary_blocks;
  std::unordered_set<const subroutine_analyzer::basic_block*> used_blocks;
  for (const auto& block : secondary.basic_blocks) {
    secondary_blocks[block.match_hash].push_back(&block);
  }

  for (size_t i = 0; i < std::min(primary.basic_blocks.size(), secondary.basic_blocks.size()); ++i) {
    const auto& bb1 = primary.basic_blocks[i];
    const auto& bb2 = secondary.basic_blocks[i];
    const subroutine_analyzer::basic_block* matched_bb2 = nullptr;
    if (!used_blocks.contains(&bb2) && bb1.match_keys == bb2.match_keys) {
      matched_bb2 = &bb2;
    } else {
      if (const auto it = secondary_blocks.find(bb1.match_hash); it != secondary_blocks.end()) {
        const auto match = std::ranges::find_if(it->second, [&](const auto* block) {
          return !used_blocks.contains(block) && block->match_keys == bb1.match_keys;
        });
        if (match != it->second.end()) {
          matched_bb2 = *match;
        }
      }
    }
    if (matched_bb2 == nullptr && !used_blocks.contains(&bb2)) {
      matched_bb2 = &bb2;
    }
    if (matched_bb2 == nullptr) {
      const auto match = std::ranges::find_if(secondary.basic_blocks, [&](const auto& block) {
        return !used_blocks.contains(&block);
      });
      matched_bb2 = &*match;
    }

    const auto distance = block_distance(bb1, *matched_bb2);
    const auto maximum_instructions =
      std::max({size_t{1}, bb1.instruction_keys.size(), matched_bb2->instruction_keys.size()});
    double block_similarity = 1.0 - static_cast<double>(distance) / (static_cast<double>(maximum_instructions) * 100.0);
    if (block_similarity < 0.3) {
      double best_similarity = block_similarity;
      for (const auto& other_bb : secondary.basic_blocks) {
        if (&other_bb == matched_bb2 || used_blocks.contains(&other_bb)) {
          continue;
        }
        if (block_upper_bound(bb1, other_bb) <= best_similarity) {
          continue;
        }
        auto curr_distance = block_distance(bb1, other_bb);
        const auto maximum_instructions =
          std::max({size_t{1}, bb1.instruction_keys.size(), other_bb.instruction_keys.size()});
        double curr_similarity =
          1.0 - static_cast<double>(curr_distance) / (static_cast<double>(maximum_instructions) * 100.0);
        if (curr_similarity > best_similarity) {
          best_similarity = curr_similarity;
          matched_bb2 = &other_bb;
        }
      }
      block_similarity = best_similarity;
    }
    if (block_similarity < 0.3) {
      continue;
    }

    used_blocks.insert(matched_bb2);
    matches.push_back({
      .primary_index = i,
      .secondary_index = static_cast<size_t>(matched_bb2 - secondary.basic_blocks.data()),
    });
  }
  return matches;
}

double
binary_differ::score_subroutines(const subroutine_analyzer::subroutine& s1, const subroutine_analyzer::subroutine& s2) {
  double total_similarity = 0.0;
  const auto block_matches = match_blocks(s1, s2);
  const auto block_map = make_block_map(s1.basic_blocks.size(), block_matches);
  for (const auto& match : block_matches) {
    const auto& bb1 = s1.basic_blocks[match.primary_index];
    const auto& bb2 = s2.basic_blocks[match.secondary_index];
    const auto same_flow = has_same_flow(s1, s2, std::span(&match, 1), block_map);
    if (bb1.instruction_keys.empty() && bb2.instruction_keys.empty()) {
      total_similarity += same_flow ? 1.0 : 0.9;
      continue;
    }

    const auto distance = block_distance(bb1, bb2);
    const auto maximum_instructions = std::max({size_t{1}, bb1.instruction_keys.size(), bb2.instruction_keys.size()});
    double block_similarity = 1.0 - static_cast<double>(distance) / (static_cast<double>(maximum_instructions) * 100.0);
    if (!same_flow) {
      block_similarity *= 0.9;
    }
    total_similarity += std::max(0.0, block_similarity);
  }

  const auto max_blocks = std::max({size_t{1}, s1.basic_blocks.size(), s2.basic_blocks.size()});
  return total_similarity / static_cast<double>(max_blocks);
}

std::vector<binary_differ::match_index> binary_differ::match_subroutines(
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

  struct match_candidate {
    double similarity;
    const subroutine_analyzer::subroutine* primary;
    const subroutine_analyzer::subroutine* secondary;
  };
  using candidate_pair = std::pair<const subroutine_analyzer::subroutine*, const subroutine_analyzer::subroutine*>;

  auto sort_candidates = [](const match_candidate& lhs, const match_candidate& rhs) {
    if (lhs.similarity != rhs.similarity) {
      return lhs.similarity > rhs.similarity;
    }

    const auto lhs_primary = lhs.primary->start_address;
    const auto lhs_secondary = lhs.secondary->start_address;
    const auto rhs_primary = rhs.primary->start_address;
    const auto rhs_secondary = rhs.secondary->start_address;

    const bool lhs_exact = lhs_primary == lhs_secondary;
    const bool rhs_exact = rhs_primary == rhs_secondary;
    if (lhs_exact != rhs_exact) {
      return lhs_exact;
    }

    const auto lhs_distance = address_distance(lhs_primary, lhs_secondary);
    const auto rhs_distance = address_distance(rhs_primary, rhs_secondary);
    if (lhs_distance != rhs_distance) {
      return lhs_distance < rhs_distance;
    }

    if (lhs_primary != rhs_primary) {
      return lhs_primary < rhs_primary;
    }
    return lhs_secondary < rhs_secondary;
  };

  std::vector<match_index> matches;
  matches.reserve(std::min(primary_subroutines.size(), secondary_subroutines.size()));
  std::set<uint64_t> matched_primary_addrs;
  std::set<uint64_t> matched_secondary_addrs;

  auto resolve_matches = [&](const std::vector<match_candidate>& candidates) {
    for (const auto& candidate : candidates) {
      if (
        matched_primary_addrs.contains(candidate.primary->start_address) ||
        matched_secondary_addrs.contains(candidate.secondary->start_address)
      ) {
        continue;
      }
      matches.push_back({
        .primary_index = static_cast<size_t>(candidate.primary - primary_subroutines.data()),
        .secondary_index = static_cast<size_t>(candidate.secondary - secondary_subroutines.data()),
        .similarity = candidate.similarity,
      });
      matched_primary_addrs.insert(candidate.primary->start_address);
      matched_secondary_addrs.insert(candidate.secondary->start_address);
    }
  };

  std::vector<candidate_pair> exact_pairs;
  exact_pairs.reserve(primary_subroutines.size());
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

    std::unordered_map<uint64_t, std::vector<const subroutine_analyzer::subroutine*>> secondary_hashes;
    for (const auto* secondary_sub : secondary_bucket) {
      secondary_hashes[secondary_sub->instruction_hash].push_back(secondary_sub);
    }
    std::unordered_map<uint64_t, size_t> hash_indices;
    std::set<uint64_t> paired_addresses;
    std::vector<const subroutine_analyzer::subroutine*> remaining_primary;
    for (const auto* primary_sub : primary_bucket) {
      auto hash_it = secondary_hashes.find(primary_sub->instruction_hash);
      if (hash_it == secondary_hashes.end()) {
        remaining_primary.push_back(primary_sub);
        continue;
      }
      auto& hash_index = hash_indices[primary_sub->instruction_hash];
      if (hash_index >= hash_it->second.size()) {
        remaining_primary.push_back(primary_sub);
        continue;
      }
      const auto* secondary_sub = hash_it->second[hash_index++];
      exact_pairs.emplace_back(primary_sub, secondary_sub);
      paired_addresses.insert(secondary_sub->start_address);
    }

    std::vector<const subroutine_analyzer::subroutine*> remaining_secondary;
    for (const auto* secondary_sub : secondary_bucket) {
      if (!paired_addresses.contains(secondary_sub->start_address)) {
        remaining_secondary.push_back(secondary_sub);
      }
    }
    const auto remaining_count = std::min(remaining_primary.size(), remaining_secondary.size());
    for (size_t i = 0; i < remaining_count; ++i) {
      exact_pairs.emplace_back(remaining_primary[i], remaining_secondary[i]);
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
            const auto similarity =
              blocks_equal(*primary_sub, *secondary_sub) ? 1.0 : score_subroutines(*primary_sub, *secondary_sub);
            if (similarity > options_.match_threshold) {
              output.push_back({.similarity = similarity, .primary = primary_sub, .secondary = secondary_sub});
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
    if (options_.delta_limit == 0 || address_deltas.size() >= options_.delta_limit) {
      break;
    }
    if (count < 16) {
      continue;
    }
    if (!std::ranges::contains(address_deltas, delta)) {
      address_deltas.push_back(delta);
    }
  }

  std::unordered_map<uint64_t, const subroutine_analyzer::subroutine*> secondary_by_address;
  for (const auto& sub : secondary_subroutines) {
    secondary_by_address.emplace(sub.start_address, &sub);
  }

  auto anchors = matches;
  std::ranges::sort(anchors, [&](const auto& lhs, const auto& rhs) {
    return primary_subroutines[lhs.primary_index].start_address < primary_subroutines[rhs.primary_index].start_address;
  });

  std::vector<candidate_pair> address_pairs;
  for (const auto& primary_sub : primary_subroutines) {
    if (matched_primary_addrs.contains(primary_sub.start_address)) {
      continue;
    }

    std::vector<uint64_t> candidate_addresses;
    auto add_candidate = [&](int64_t delta) {
      const auto address = add_delta(primary_sub.start_address, delta);
      if (address && !std::ranges::contains(candidate_addresses, *address)) {
        candidate_addresses.push_back(*address);
      }
    };
    for (const auto delta : address_deltas) {
      add_candidate(delta);
    }

    const auto anchor_it = std::lower_bound(
      anchors.begin(), anchors.end(), primary_sub.start_address, [&](const auto& match, uint64_t address) {
        return primary_subroutines[match.primary_index].start_address < address;
      }
    );
    auto add_anchor = [&](const match_index& match) {
      add_candidate(address_delta(
        primary_subroutines[match.primary_index].start_address,
        secondary_subroutines[match.secondary_index].start_address
      ));
    };
    if (anchor_it != anchors.end()) {
      add_anchor(*anchor_it);
    }
    if (anchor_it != anchors.begin()) {
      add_anchor(*std::prev(anchor_it));
    }

    for (const auto secondary_address : candidate_addresses) {
      auto secondary_it = secondary_by_address.find(secondary_address);
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
            const auto similarity = score_subroutines(*primary_sub, *secondary_sub);
            if (similarity > options_.match_threshold) {
              output.push_back({.similarity = similarity, .primary = primary_sub, .secondary = secondary_sub});
            }
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

  if (options_.fallback_limit == 0) {
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
              const auto similarity = score_subroutines(*primary_sub, *secondary_sub);
              if (similarity > options_.fallback_threshold) {
                output.push_back({.similarity = similarity, .primary = primary_sub, .secondary = secondary_sub});
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

    size_t scored_count = 0;
    for (const auto& candidates : scored_candidates) {
      scored_count += candidates.size();
    }
    std::vector<match_candidate> fallback_matches;
    fallback_matches.reserve(scored_count);
    for (auto& candidates : scored_candidates) {
      fallback_matches.insert(
        fallback_matches.end(), std::make_move_iterator(candidates.begin()), std::make_move_iterator(candidates.end())
      );
    }

    std::ranges::sort(fallback_matches, sort_candidates);
    resolve_matches(fallback_matches);
  }

  return matches;
}
