#pragma once
#include <cstdint>

using elf64_addr = uint64_t;
using elf64_off = uint64_t;
using elf64_half = uint16_t;
using elf64_word = uint32_t;
using elf64_xword = uint64_t;

constexpr int EI_NIDENT = 16;

#pragma pack(push, 1)
struct elf64_ehdr {
  unsigned char e_ident[EI_NIDENT];
  elf64_half e_type;
  elf64_half e_machine;
  elf64_word e_version;
  elf64_addr e_entry;
  elf64_off e_phoff;
  elf64_off e_shoff;
  elf64_word e_flags;
  elf64_half e_ehsize;
  elf64_half e_phentsize;
  elf64_half e_phnum;
  elf64_half e_shentsize;
  elf64_half e_shnum;
  elf64_half e_shstrndx;
};

struct elf64_shdr {
  elf64_word sh_name;
  elf64_word sh_type;
  elf64_xword sh_flags;
  elf64_addr sh_addr;
  elf64_off sh_offset;
  elf64_xword sh_size;
  elf64_word sh_link;
  elf64_word sh_info;
  elf64_xword sh_addralign;
  elf64_xword sh_entsize;
};
#pragma pack(pop)

// e_ident[] indices
constexpr int EI_MAG0 = 0;
constexpr int EI_MAG1 = 1;
constexpr int EI_MAG2 = 2;
constexpr int EI_MAG3 = 3;

// e_ident[EI_MAG] values
constexpr char ELFMAG0 = 0x7f;
constexpr char ELFMAG1 = 'E';
constexpr char ELFMAG2 = 'L';
constexpr char ELFMAG3 = 'F';

