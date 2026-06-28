#include "parser.h"
#include <algorithm>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>
#include "headers/elf_header.h"
#include "headers/pe_header.h"

namespace {

  constexpr uint8_t dw_eh_pe_omit = 0xff;
  constexpr uint8_t dw_eh_pe_absptr = 0x00;
  constexpr uint8_t dw_eh_pe_uleb128 = 0x01;
  constexpr uint8_t dw_eh_pe_udata2 = 0x02;
  constexpr uint8_t dw_eh_pe_udata4 = 0x03;
  constexpr uint8_t dw_eh_pe_udata8 = 0x04;
  constexpr uint8_t dw_eh_pe_sleb128 = 0x09;
  constexpr uint8_t dw_eh_pe_sdata2 = 0x0a;
  constexpr uint8_t dw_eh_pe_sdata4 = 0x0b;
  constexpr uint8_t dw_eh_pe_sdata8 = 0x0c;
  constexpr uint8_t dw_eh_pe_format_mask = 0x0f;
  constexpr uint8_t dw_eh_pe_pcrel = 0x10;
  constexpr uint8_t dw_eh_pe_datarel = 0x30;
  constexpr uint8_t dw_eh_pe_application_mask = 0x70;
  constexpr uint8_t dw_eh_pe_indirect = 0x80;

  template <typename value_type>
  [[nodiscard]] auto read_little_endian(std::span<const uint8_t> data, size_t& offset) -> std::optional<value_type> {
    if (sizeof(value_type) > data.size() - offset) {
      return std::nullopt;
    }

    value_type value{};
    std::memcpy(&value, data.data() + offset, sizeof(value_type));
    offset += sizeof(value_type);
    return value;
  }

  [[nodiscard]] auto read_uleb128(std::span<const uint8_t> data, size_t& offset) -> std::optional<uint64_t> {
    uint64_t result = 0;
    uint32_t shift = 0;

    while (offset < data.size() && shift < 64) {
      const auto byte = data[offset++];
      result |= static_cast<uint64_t>(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) {
        return result;
      }
      shift += 7;
    }

    return std::nullopt;
  }

  [[nodiscard]] auto read_sleb128(std::span<const uint8_t> data, size_t& offset) -> std::optional<int64_t> {
    uint64_t result = 0;
    uint32_t shift = 0;
    uint8_t byte = 0;

    while (offset < data.size() && shift < 64) {
      byte = data[offset++];
      result |= static_cast<uint64_t>(byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) == 0) {
        if (shift < 64 && (byte & 0x40) != 0) {
          result |= (~uint64_t{0}) << shift;
        }
        return static_cast<int64_t>(result);
      }
    }

    return std::nullopt;
  }

  [[nodiscard]] auto add_signed(uint64_t lhs, int64_t rhs) -> uint64_t {
    if (rhs < 0) {
      return lhs - static_cast<uint64_t>(-rhs);
    }
    return lhs + static_cast<uint64_t>(rhs);
  }

  [[nodiscard]] auto
  decode_eh_value(std::span<const uint8_t> data, size_t& offset, uint8_t encoding, uint64_t section_address)
    -> std::optional<uint64_t> {
    // decode dwarf eh pointer encodings without reading the full frame data
    if (encoding == dw_eh_pe_omit || (encoding & dw_eh_pe_indirect) != 0) {
      return std::nullopt;
    }

    const auto value_address = section_address + offset;
    uint64_t raw_unsigned = 0;
    int64_t raw_signed = 0;
    bool is_signed = false;

    switch (encoding & dw_eh_pe_format_mask) {
      case dw_eh_pe_absptr: {
        auto value = read_little_endian<uint64_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_unsigned = *value;
        break;
      }
      case dw_eh_pe_uleb128: {
        auto value = read_uleb128(data, offset);
        if (!value)
          return std::nullopt;
        raw_unsigned = *value;
        break;
      }
      case dw_eh_pe_udata2: {
        auto value = read_little_endian<uint16_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_unsigned = *value;
        break;
      }
      case dw_eh_pe_udata4: {
        auto value = read_little_endian<uint32_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_unsigned = *value;
        break;
      }
      case dw_eh_pe_udata8: {
        auto value = read_little_endian<uint64_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_unsigned = *value;
        break;
      }
      case dw_eh_pe_sleb128: {
        auto value = read_sleb128(data, offset);
        if (!value)
          return std::nullopt;
        raw_signed = *value;
        is_signed = true;
        break;
      }
      case dw_eh_pe_sdata2: {
        auto value = read_little_endian<int16_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_signed = *value;
        is_signed = true;
        break;
      }
      case dw_eh_pe_sdata4: {
        auto value = read_little_endian<int32_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_signed = *value;
        is_signed = true;
        break;
      }
      case dw_eh_pe_sdata8: {
        auto value = read_little_endian<int64_t>(data, offset);
        if (!value)
          return std::nullopt;
        raw_signed = *value;
        is_signed = true;
        break;
      }
      default:
        return std::nullopt;
    }

    auto value = is_signed ? add_signed(0, raw_signed) : raw_unsigned;
    switch (encoding & dw_eh_pe_application_mask) {
      case 0:
        return value;
      case dw_eh_pe_pcrel:
        return is_signed ? add_signed(value_address, raw_signed) : value_address + raw_unsigned;
      case dw_eh_pe_datarel:
        return is_signed ? add_signed(section_address, raw_signed) : section_address + raw_unsigned;
      default:
        return std::nullopt;
    }
  }

} // namespace

binary_parser::binary_parser(const std::string& path) : path_(path), image_base_(0) {
  detect_and_parse();
}

void binary_parser::detect_and_parse() {
  std::ifstream file(path_, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open file: " + path_);
  }

  char magic[4];
  file.read(magic, 4);
  file.seekg(0);

  if (magic[0] == 'M' && magic[1] == 'Z') {
    LOG("PE file.\n");
    parse_pe(file);
    return;
  }

  if (magic[0] == ELFMAG0 && magic[1] == ELFMAG1 && magic[2] == ELFMAG2 && magic[3] == ELFMAG3) {
    LOG("ELF file.\n");
    parse_elf(file);
    return;
  }

  throw std::runtime_error("Unsupported or unknown file format: " + path_);
}

void binary_parser::parse_pe(std::ifstream& file) {
  LOG("Parsing PE file: %s\n", path_.c_str());

  dos_header d_header;
  file.read(reinterpret_cast<char*>(&d_header), sizeof(d_header));
  if (d_header.e_magic != IMAGE_DOS_SIGNATURE) {
    throw std::runtime_error("Invalid DOS signature");
  }

  file.seekg(d_header.e_lfanew);
  uint32_t nt_signature;
  file.read(reinterpret_cast<char*>(&nt_signature), sizeof(nt_signature));
  if (nt_signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("Invalid NT signature");
  }

  file_header f_header;
  file.read(reinterpret_cast<char*>(&f_header), sizeof(f_header));

  optional_header_64 opt_header;
  file.read(reinterpret_cast<char*>(&opt_header), sizeof(opt_header));

  image_base_ = opt_header.image_base;
  LOG("Image base: 0x%llx\n", image_base_);

  file.seekg(d_header.e_lfanew + sizeof(nt_signature) + sizeof(f_header) + f_header.size_of_optional_header);

  for (int i = 0; i < f_header.number_of_sections; i++) {
    section_header s_header;
    file.read(reinterpret_cast<char*>(&s_header), sizeof(s_header));

    section sect;
    sect.name = std::string(s_header.name, strnlen(s_header.name, 8));
    sect.virtual_address = s_header.virtual_address;
    sect.size = s_header.size_of_raw_data;
    sect.file_offset = s_header.pointer_to_raw_data;
    sect.flags = 0;

    LOG("Found section: %s, VA: 0x%x, Size: 0x%x\n", sect.name.c_str(), sect.virtual_address, sect.size);

    std::streampos current_pos = file.tellg();
    file.seekg(s_header.pointer_to_raw_data);
    sect.data.resize(s_header.size_of_raw_data);
    file.read(reinterpret_cast<char*>(sect.data.data()), s_header.size_of_raw_data);
    file.seekg(current_pos);

    sections_.push_back(std::move(sect));
  }
}

void binary_parser::parse_elf(std::ifstream& file) {
  LOG("Parsing ELF file: %s\n", path_.c_str());

  elf64_ehdr elf_header;
  file.read(reinterpret_cast<char*>(&elf_header), sizeof(elf_header));

  image_base_ = 0;
  LOG("Image base (ELF): 0x%llx\n", image_base_);

  if (elf_header.e_shstrndx == 0 || elf_header.e_shoff == 0) {
    LOG("No section header string table or section headers found\n");
    return;
  }

  elf64_shdr shstrtab_header;
  file.seekg(elf_header.e_shoff + elf_header.e_shstrndx * elf_header.e_shentsize);
  file.read(reinterpret_cast<char*>(&shstrtab_header), sizeof(shstrtab_header));

  std::vector<char> string_table(shstrtab_header.sh_size);
  file.seekg(shstrtab_header.sh_offset);
  file.read(string_table.data(), shstrtab_header.sh_size);

  file.seekg(elf_header.e_shoff);
  for (int i = 0; i < elf_header.e_shnum; ++i) {
    elf64_shdr section_h;
    file.read(reinterpret_cast<char*>(&section_h), sizeof(section_h));

    if (section_h.sh_name != 0) {
      section sect;
      sect.name = std::string(string_table.data() + section_h.sh_name);
      sect.virtual_address = section_h.sh_addr;
      sect.size = section_h.sh_size;
      sect.file_offset = section_h.sh_offset;
      sect.flags = section_h.sh_flags;

      LOG("Found section: %s, VA: 0x%llx, Size: 0x%llx\n", sect.name.c_str(), sect.virtual_address, sect.size);

      if (section_h.sh_size > 0 && section_h.sh_offset > 0) {
        std::streampos current_pos = file.tellg();
        file.seekg(section_h.sh_offset);
        sect.data.resize(section_h.sh_size);
        file.read(reinterpret_cast<char*>(sect.data.data()), section_h.sh_size);
        file.seekg(current_pos);
      }

      sections_.push_back(std::move(sect));
    }
  }

  parse_elf_frame_header();
}

const binary_parser::section* binary_parser::get_text_section() const {
  for (const auto& sect : sections_) {
    if (sect.name.starts_with(".text")) {
      LOG("Found .text section with %zu bytes of data\n", sect.data.size());
      for (size_t i = 0; i < (std::min)(size_t(16), sect.data.size()); i++) {
        LOG("%02x ", sect.data[i]);
      }
      LOG("\n");
      return &sect;
    }
  }
  return nullptr;
}

const binary_parser::section* binary_parser::get_section(std::string_view name) const {
  for (const auto& sect : sections_) {
    if (sect.name == name) {
      return &sect;
    }
  }
  return nullptr;
}

const std::vector<uint64_t>& binary_parser::get_function_starts() const {
  return function_starts_;
}

uint64_t binary_parser::get_image_base() const {
  return image_base_;
}

void binary_parser::parse_elf_frame_header() {
  const auto* frame_header = get_section(".eh_frame_hdr");
  const auto* text = get_text_section();
  if (frame_header == nullptr || text == nullptr || frame_header->data.size() < 4) {
    return;
  }

  const std::span<const uint8_t> data(frame_header->data);
  size_t offset = 0;
  const auto version = data[offset++];
  const auto frame_ptr_encoding = data[offset++];
  const auto fde_count_encoding = data[offset++];
  const auto table_encoding = data[offset++];
  if (version != 1 || fde_count_encoding == dw_eh_pe_omit || table_encoding == dw_eh_pe_omit) {
    return;
  }

  if (!decode_eh_value(data, offset, frame_ptr_encoding, frame_header->virtual_address)) {
    return;
  }

  const auto fde_count = decode_eh_value(data, offset, fde_count_encoding, frame_header->virtual_address);
  if (!fde_count) {
    return;
  }

  const auto text_begin = text->virtual_address;
  const auto text_end = text_begin + text->size;
  function_starts_.clear();
  function_starts_.reserve(static_cast<size_t>(*fde_count));

  // use unwind entries as starts for stripped elf binaries
  for (uint64_t i = 0; i < *fde_count; ++i) {
    auto function_start = decode_eh_value(data, offset, table_encoding, frame_header->virtual_address);
    auto fde_address = decode_eh_value(data, offset, table_encoding, frame_header->virtual_address);
    if (!function_start || !fde_address) {
      function_starts_.clear();
      return;
    }

    if (*function_start >= text_begin && *function_start < text_end) {
      function_starts_.push_back(*function_start);
    }
  }

  std::ranges::sort(function_starts_);
  function_starts_.erase(std::ranges::unique(function_starts_).begin(), function_starts_.end());
}
