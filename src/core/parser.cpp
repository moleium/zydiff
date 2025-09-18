#include "parser.h"
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <windows.h>

binary_parser::binary_parser(const std::string& path) : path_(path), image_base_(0) {
  parse_pe();
}

void binary_parser::parse_pe() {
  std::ifstream file(path_, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open file: " + path_);
  }

  LOG("Parsing PE file: %s\n", path_.c_str());

  IMAGE_DOS_HEADER dos_header;
  file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
  if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
    throw std::runtime_error("Invalid DOS signature");
  }

  file.seekg(dos_header.e_lfanew);
  IMAGE_NT_HEADERS nt_headers;
  file.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));
  if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("Invalid NT signature");
  }

  image_base_ = nt_headers.OptionalHeader.ImageBase;
  LOG("Image base: 0x%llx\n", image_base_);

  IMAGE_SECTION_HEADER section_header;
  for (int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
    file.read(reinterpret_cast<char*>(&section_header), sizeof(section_header));

    section sect;
    sect.name = std::string(reinterpret_cast<char*>(section_header.Name), 8);
    sect.virtual_address = section_header.VirtualAddress;
    sect.size = section_header.SizeOfRawData;

    LOG("Found section: %s, VA: 0x%x, Size: 0x%x\n", sect.name.c_str(), sect.virtual_address, sect.size);

    auto current_pos = file.tellg();
    file.seekg(section_header.PointerToRawData);
    sect.data.resize(section_header.SizeOfRawData);
    file.read(reinterpret_cast<char*>(sect.data.data()), section_header.SizeOfRawData);
    file.seekg(current_pos);

    sections_.push_back(std::move(sect));
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
