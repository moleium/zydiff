#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class string_diff {
  public:
  struct options {
    size_t min_length{4};
    size_t max_xrefs_per_string{8};
  };

  struct string_entry {
    uint64_t address{};
    std::string section;
    std::string value;
    std::vector<uint64_t> xrefs;
  };

  struct result {
    size_t primary_string_count{};
    size_t secondary_string_count{};
    std::vector<string_entry> added;
    std::vector<string_entry> removed;
  };

  [[nodiscard]] static result compare(const std::string& primary_path, const std::string& secondary_path, options opts);
};
