#define DEBUG 1

#include "core/differ.h"
#include "util/logger.h"
#include <iostream>

void formatResults(const BinaryDiffer::DiffResult &result) {
  LOG("Matched functions: %zu\n", result.matched_functions.size());
  LOG("Unmatched in primary: %zu\n", result.unmatched_primary.size());
  LOG("Unmatched in secondary: %zu\n\n", result.unmatched_secondary.size());

  LOG("Function matches:\n");
  for (const auto &[primary, secondary] : result.matched_functions) {
    LOG("%016llx -> %016llx (similarity: %.2f%%)\n", primary.start_address,
        secondary.start_address, primary.similarity_score * 100);

    if (primary.similarity_score < 1.0 && !primary.diff_details.empty()) {
      LOG("Changes:\n");
      for (const auto &detail : primary.diff_details) {
        LOG("%s", detail.c_str());
      }
      LOG("\n");
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0]
              << " <primary_binary> <secondary_binary>\n";
    return 1;
  }

  try {
    BinaryDiffer differ(argv[1], argv[2]);
    auto result = differ.Compare();
    formatResults(result);
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  return 0;
}