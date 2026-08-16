#include "core/strings.h"
#include <algorithm>
#include <cstring>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include "decoder.h"
#include "headers/elf_header.h"
#include "headers/pe_header.h"
#include "parser.h"

namespace {

  [[nodiscard]] auto is_executable_section(const binary_parser::section& section) -> bool {
    return (section.flags & SHF_EXECINSTR) != 0 || (section.flags & IMAGE_SCN_MEM_EXECUTE) != 0;
  }

  [[nodiscard]] auto is_string_section(const binary_parser::section& section) -> bool {
    if (section.data.empty() || is_executable_section(section)) {
      return false;
    }
    if (
      section.name.contains("debug") || section.name == ".symtab" || section.name == ".strtab" ||
      section.name == ".shstrtab"
    ) {
      return false;
    }
    return (section.flags & SHF_ALLOC) != 0 || section.name.contains("data") || section.name.contains("rdata") ||
           section.name.contains("rodata") || section.name == ".dynstr";
  }

  [[nodiscard]] auto is_string_byte(uint8_t value) -> bool {
    return value == '\t' || (value >= 0x20 && value <= 0x7e);
  }

  [[nodiscard]] auto read_u32(const uint8_t* data) -> uint32_t {
    uint32_t value{};
    std::memcpy(&value, data, sizeof(value));
    return value;
  }

  [[nodiscard]] auto read_u64(const uint8_t* data) -> uint64_t {
    uint64_t value{};
    std::memcpy(&value, data, sizeof(value));
    return value;
  }

  [[nodiscard]] auto extract_strings(const binary_parser& parser, size_t min_length) -> std::vector<strings::entry> {
    std::vector<strings::entry> strings;

    for (const auto& section : parser.get_sections()) {
      if (!is_string_section(section)) {
        continue;
      }

      size_t start = 0;
      while (start < section.data.size()) {
        while (start < section.data.size() && !is_string_byte(section.data[start])) {
          ++start;
        }

        auto end = start;
        while (end < section.data.size() && is_string_byte(section.data[end])) {
          ++end;
        }

        if (end - start >= min_length && end < section.data.size() && section.data[end] == 0) {
          strings.push_back({
            .address = section.virtual_address + start,
            .section = section.name,
            .value = std::string(reinterpret_cast<const char*>(section.data.data() + start), end - start),
            .xrefs = {},
          });
        }

        start = end + 1;
      }
    }

    return strings;
  }

  [[nodiscard]] auto resolve_address(const binary_parser::section& text, size_t match_offset)
    -> std::optional<uint64_t> {
    const auto search_begin = match_offset > 15 ? match_offset - 15 : 0;
    decoder code_decoder;

    for (size_t candidate = search_begin; candidate <= match_offset; ++candidate) {
      size_t offset = candidate;
      while (offset <= match_offset) {
        const auto address = text.virtual_address + offset;
        if (!code_decoder.disassemble(address, text.data.data() + offset, text.data.size() - offset)) {
          break;
        }

        const auto instruction = code_decoder.get_decoded_instruction();
        if (match_offset < offset + instruction.length) {
          return address;
        }
        offset += instruction.length;
      }
    }

    return std::nullopt;
  }

  void attach_xrefs(const binary_parser& parser, std::vector<strings::entry>& strings, size_t reference_limit) {
    const auto* text = parser.get_text_section();
    if (text == nullptr || text->data.empty() || strings.empty()) {
      return;
    }

    std::unordered_map<uint64_t, std::vector<size_t>> strings_by_address;
    strings_by_address.reserve(strings.size());
    for (size_t i = 0; i < strings.size(); ++i) {
      strings_by_address[strings[i].address].push_back(i);
    }

    std::unordered_map<size_t, uint64_t> address_cache;

    auto get_address = [&](size_t match_offset) {
      auto it = address_cache.find(match_offset);
      if (it != address_cache.end()) {
        return it->second;
      }

      const auto resolved = resolve_address(*text, match_offset).value_or(text->virtual_address + match_offset);
      address_cache.emplace(match_offset, resolved);
      return resolved;
    };

    auto add_xref = [&](uint64_t target, size_t match_offset) {
      auto it = strings_by_address.find(target);
      if (it == strings_by_address.end()) {
        return;
      }
      const auto xref_address = get_address(match_offset);
      for (auto string_index : it->second) {
        auto& xrefs = strings[string_index].xrefs;
        if (xrefs.size() < reference_limit && !std::ranges::contains(xrefs, xref_address)) {
          xrefs.push_back(xref_address);
        }
      }
    };

    for (size_t offset = 0; offset < text->data.size(); ++offset) {
      if (offset + sizeof(uint32_t) <= text->data.size()) {
        add_xref(read_u32(text->data.data() + offset), offset);
      }
      if (offset + sizeof(uint64_t) <= text->data.size()) {
        add_xref(read_u64(text->data.data() + offset), offset);
      }
    }
  }

  [[nodiscard]] auto diff_strings(const std::vector<strings::entry>& source, const std::vector<strings::entry>& other)
    -> std::vector<strings::entry> {
    std::unordered_set<std::string_view> other_values;
    other_values.reserve(other.size());
    for (const auto& entry : other) {
      other_values.insert(entry.value);
    }

    std::vector<strings::entry> result;
    std::unordered_set<std::string_view> emitted_values;
    emitted_values.reserve(source.size());
    for (const auto& entry : source) {
      if (other_values.contains(entry.value) || emitted_values.contains(entry.value)) {
        continue;
      }
      result.push_back(entry);
      emitted_values.insert(entry.value);
    }

    std::ranges::sort(result, [](const auto& lhs, const auto& rhs) {
      const auto lhs_xrefs = !lhs.xrefs.empty();
      const auto rhs_xrefs = !rhs.xrefs.empty();
      if (lhs_xrefs != rhs_xrefs) {
        return lhs_xrefs > rhs_xrefs;
      }
      return lhs.address < rhs.address;
    });
    return result;
  }

} // namespace

strings::result strings::compare(const std::string& primary_path, const std::string& secondary_path, options opts) {
  binary_parser primary(primary_path);
  binary_parser secondary(secondary_path);

  auto primary_strings = extract_strings(primary, opts.min_length);
  auto secondary_strings = extract_strings(secondary, opts.min_length);
  attach_xrefs(primary, primary_strings, opts.reference_limit);
  attach_xrefs(secondary, secondary_strings, opts.reference_limit);

  return {
    .primary_count = primary_strings.size(),
    .secondary_count = secondary_strings.size(),
    .added = diff_strings(secondary_strings, primary_strings),
    .removed = diff_strings(primary_strings, secondary_strings),
  };
}
