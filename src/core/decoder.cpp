#include "decoder.h"

decoder::decoder() {
  ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
}

auto decoder::disassemble(uint64_t address, const unsigned char* data, size_t size) -> bool {
  success_ = false;
  if (data == nullptr || size == 0) {
    return false;
  }

  address_ = address;
  if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, data, size, &instruction_.info, instruction_.operands))) {
    return false;
  }

  success_ = true;
  return true;
}

[[nodiscard]] auto decoder::get_instruction() -> std::string {
  if (!success_) {
    return "???";
  }
  char text[256]{};
  if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
        &formatter_, &instruction_.info, instruction_.operands, instruction_.info.operand_count, text, sizeof(text),
        address_, nullptr
      ))) {
    return "???";
  }
  return text;
}

[[nodiscard]] auto decoder::get_decoded_instruction() const -> const ZydisDecodedInstruction& {
  return instruction_.info;
}

[[nodiscard]] auto decoder::get_decoded_operands() const -> const ZydisDecodedOperand* {
  return instruction_.operands;
}
