#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "logger.h"

class BinaryParser {
  public:
  struct Section {
    std::string name;
    uint64_t virtual_address;
    uint64_t size;
    std::vector<uint8_t> data;
  };

  BinaryParser(const std::string& path);

  [[nodiscard]] auto GetTextSection() const -> const Section*;
  [[nodiscard]] auto GetImageBase() const -> uint64_t;

  private:
  void ParsePE();

  std::string path_;
  uint64_t image_base_;
  std::vector<Section> sections_;
};
