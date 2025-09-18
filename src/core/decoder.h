#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <Zydis/Zydis.h>

#include <format>
#include <string>

class zydis {
  public:
  zydis();

  auto disassemble(uint64_t address, const unsigned char* data, size_t size) -> bool;

  [[nodiscard]] auto get_instruction() const -> std::string;
  [[nodiscard]] auto get_instruction_bytes(const unsigned char* data) const -> std::string;
  [[nodiscard]] auto get_instruction_address() const -> uint64_t;
  [[nodiscard]] auto get_visible_operand_count() const -> int;
  [[nodiscard]] auto get_decoded_instruction() const -> ZydisDecodedInstruction;
  [[nodiscard]] auto get_decoded_operands() const -> const ZydisDecodedOperand*;

  private:
  ZydisDecoder decoder_;
  ZydisFormatter formatter_;
  uint64_t address_;
  bool success_;
  int visible_operand_count_;
  char instruction_text_[256];
  struct Instruction {
    ZydisDecodedInstruction info;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  } instruction_;
};

