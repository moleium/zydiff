#pragma once

#include <expected>
#include <string>
#include "differ.h"

class diff_serializer {
  public:
  [[nodiscard]] static auto save(const binary_differ::diff_result& result, const std::string& filepath) -> bool;
  [[nodiscard]] static auto load(const std::string& filepath) -> std::expected<binary_differ::diff_result, std::string>;
};
