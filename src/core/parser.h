#pragma once

#include "logger.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class binary_parser {
  public:
  struct section {
    std::string name;
    uint64_t virtual_address;
    uint64_t size;
    std::vector<uint8_t> data;
  };

  binary_parser(const std::string& path);

  [[nodiscard]] const section* get_text_section() const;
  [[nodiscard]] uint64_t get_image_base() const;

  private:
  void parse_pe();

  std::string path_;
  uint64_t image_base_;
  std::vector<section> sections_;
};
