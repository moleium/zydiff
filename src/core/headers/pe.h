#pragma once
#include <cstdint>
#include <optional>
#include <vector>


constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;    // MZ
constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550; // PE00

#pragma pack(push, 1)
struct DosHeader {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
};

struct FileHeader {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct DataDirectory {
  uint32_t VirtualAddress;
  uint32_t Size;
};

struct OptionalHeader64 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  DataDirectory DataDirectory[16];
};

struct SectionHeader {
  char Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};
#pragma pack(pop)

class PEFile {
  public:
  PEFile() = default;

  static std::optional<PEFile> parse(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(DosHeader)) {
      return std::nullopt;
    }

    PEFile pe;
    pe.raw_data_ = data;

    auto* dos_header = reinterpret_cast<const DosHeader*>(data.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
      return std::nullopt;
    }
    pe.dos_header_ = *dos_header;

    size_t pe_offset = dos_header->e_lfanew;
    if (pe_offset + sizeof(uint32_t) > data.size()) {
      return std::nullopt;
    }

    auto* signature = reinterpret_cast<const uint32_t*>(data.data() + pe_offset);
    if (*signature != IMAGE_NT_SIGNATURE) {
      return std::nullopt;
    }

    pe_offset += sizeof(uint32_t);
    if (pe_offset + sizeof(FileHeader) > data.size()) {
      return std::nullopt;
    }
    pe.file_header_ = *reinterpret_cast<const FileHeader*>(data.data() + pe_offset);

    pe_offset += sizeof(FileHeader);
    if (pe_offset + sizeof(OptionalHeader64) > data.size()) {
      return std::nullopt;
    }
    pe.optional_header_ = *reinterpret_cast<const OptionalHeader64*>(data.data() + pe_offset);

    pe_offset += pe.file_header_.SizeOfOptionalHeader;
    for (uint16_t i = 0; i < pe.file_header_.NumberOfSections; i++) {
      if (pe_offset + sizeof(SectionHeader) > data.size()) {
        return std::nullopt;
      }
      pe.section_headers_.push_back(*reinterpret_cast<const SectionHeader*>(data.data() + pe_offset));
      pe_offset += sizeof(SectionHeader);
    }

    return pe;
  }

  const DosHeader& GetDosHeader() const {
    return dos_header_;
  }
  const FileHeader& GetFileHeader() const {
    return file_header_;
  }
  const OptionalHeader64& GetOptionalHeader() const {
    return optional_header_;
  }
  const std::vector<SectionHeader>& GetSectionHeaders() const {
    return section_headers_;
  }

  private:
  std::vector<uint8_t> raw_data_;
  DosHeader dos_header_{};
  FileHeader file_header_{};
  OptionalHeader64 optional_header_{};
  std::vector<SectionHeader> section_headers_;
};
