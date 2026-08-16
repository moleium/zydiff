#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class strings {
  public:
  struct options {
    size_t min_length{4};
    size_t reference_limit{8};
  };

  struct entry {
    uint64_t address{};
    std::string section;
    std::string value;
    std::vector<uint64_t> xrefs;
  };

  struct result {
    size_t primary_count{};
    size_t secondary_count{};
    std::vector<entry> added;
    std::vector<entry> removed;
  };

  [[nodiscard]] static result compare(const std::string& primary_path, const std::string& secondary_path, options opts);
};
