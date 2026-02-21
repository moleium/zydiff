#pragma once

#include "differ.h"
#include <expected>
#include <string>

class diff_serializer {
  public:
  [[nodiscard]] static auto save(const binary_differ::diff_result& result, const std::string& filepath) -> bool;
  [[nodiscard]] static auto load(const std::string& filepath) -> std::expected<binary_differ::diff_result, std::string>;
};
