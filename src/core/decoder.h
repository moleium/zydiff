#pragma once

#include <Zydis/Zydis.h>

#include <string>

class decoder {
  public:
  decoder();

  auto disassemble(uint64_t address, const unsigned char* data, size_t size) -> bool;

  [[nodiscard]] auto get_instruction() -> std::string;
  [[nodiscard]] auto get_decoded_instruction() const -> const ZydisDecodedInstruction&;
  [[nodiscard]] auto get_decoded_operands() const -> const ZydisDecodedOperand*;

  private:
  ZydisDecoder decoder_;
  ZydisFormatter formatter_;
  uint64_t address_{};
  bool success_{false};
  struct instruction_state {
    ZydisDecodedInstruction info;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  } instruction_{};
};
