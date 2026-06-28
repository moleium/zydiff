#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "logger.h"

class binary_parser {
  public:
  struct section {
    std::string name;
    uint64_t virtual_address;
    uint64_t size;
    uint64_t file_offset;
    uint64_t flags;
    std::vector<uint8_t> data;
  };

  explicit binary_parser(const std::string& path);

  [[nodiscard]] const section* get_text_section() const;
  [[nodiscard]] const section* get_section(std::string_view name) const;
  [[nodiscard]] const std::vector<uint64_t>& get_function_starts() const;
  [[nodiscard]] uint64_t get_image_base() const;

  private:
  void detect_and_parse();
  void parse_pe(std::ifstream& file);
  void parse_elf(std::ifstream& file);
  void parse_elf_frame_header();

  std::string path_;
  uint64_t image_base_;
  std::vector<section> sections_;
  std::vector<uint64_t> function_starts_;
};
