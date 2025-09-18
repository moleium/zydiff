#include "decoder.h"

zydis::zydis() {
  ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
}

auto zydis::disassemble(uint64_t address, const unsigned char* data, size_t size) -> bool {
  if (data == nullptr || size == 0)
    return false;

  address_ = address;
  success_ = false;

  if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, data, size, &instruction_.info, instruction_.operands)))
    return false;

  if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
    &formatter_,
    &instruction_.info,
    instruction_.operands,
    instruction_.info.operand_count,
    instruction_text_,
    sizeof(instruction_text_),
    address_,
    nullptr)))
    return false;

  visible_operand_count_ = 0;
  for (auto& operand : instruction_.operands)
  {
    if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN)
      break;

    if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative)
    {
      ZydisCalcAbsoluteAddress(&instruction_.info, &operand, address_, &operand.imm.value.u);
      operand.imm.is_relative = false;
    }
    else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
      operand.mem.base == ZYDIS_REGISTER_NONE &&
      operand.mem.index == ZYDIS_REGISTER_NONE &&
      operand.mem.disp.value != 0)
    {
      ZydisCalcAbsoluteAddress(&instruction_.info, &operand, address_, (uint64_t*)&operand.mem.disp.value);
    }

    ++visible_operand_count_;
  }

  success_ = true;
  return true;
}

[[nodiscard]] auto zydis::get_instruction() const -> std::string {
  if (success_) {
    return std::string(instruction_text_);
  }
  return std::string("???");
}

[[nodiscard]] auto zydis::get_instruction_bytes(const unsigned char* data) const -> std::string {
  if (success_) {
    std::string bytes;
    for (int j = 0; j < instruction_.info.length; j++) {
      bytes += std::format("{:02x} ", static_cast<int>(data[j]));
    }
    return bytes;
  }
  return std::string("???");
}

[[nodiscard]] auto zydis::get_instruction_address() const -> uint64_t {
  return address_;
}

[[nodiscard]] auto zydis::get_visible_operand_count() const -> int {
  return visible_operand_count_;
}

[[nodiscard]] auto zydis::get_decoded_instruction() const -> ZydisDecodedInstruction {
  return instruction_.info;
}

[[nodiscard]] auto zydis::get_decoded_operands() const -> const ZydisDecodedOperand* {
  return instruction_.operands;
}
