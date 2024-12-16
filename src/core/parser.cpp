#include "parser.h"
#include <windows.h>
#include <fstream>
#include <stdexcept>

BinaryParser::BinaryParser(const std::string& path) 
    : path_(path), image_base_(0) {
  ParsePE();
}

void BinaryParser::ParsePE() {
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
    
    Section section;
    section.name = std::string(reinterpret_cast<char*>(section_header.Name), 8);
    section.virtual_address = section_header.VirtualAddress;
    section.size = section_header.SizeOfRawData;
    
    LOG("Found section: %s, VA: 0x%x, Size: 0x%x\n", 
           section.name.c_str(), section.virtual_address, section.size);

    auto current_pos = file.tellg();
    file.seekg(section_header.PointerToRawData);
    section.data.resize(section_header.SizeOfRawData);
    file.read(reinterpret_cast<char*>(section.data.data()), section_header.SizeOfRawData);
    file.seekg(current_pos);

    sections_.push_back(std::move(section));
  }
}

auto BinaryParser::GetTextSection() const -> const Section* {
  for (const auto& section : sections_) {
    if (section.name.starts_with(".text")) {
      LOG("Found .text section with %zu bytes of data\n", section.data.size());
      for (size_t i = 0; i < (std::min)(size_t(16), section.data.size()); i++) {
        LOG("%02x ", section.data[i]);
      }
      LOG("\n");
      return &section;
    }
  }
  return nullptr;
}

auto BinaryParser::GetImageBase() const -> uint64_t {
  return image_base_;
} 