#include "parser.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>
#include "headers/elf_header.h"
#include "headers/pe_header.h"

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

uint64_t binary_parser::get_image_base() const {
  return image_base_;
}
