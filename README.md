# zydiff

A lightweight binary diffing library for x86-64 executables.

zydiff compares two binaries and generates a diff of the changes. using the Zydis disassembler engine.
Supports both PE (Windows) and ELF (Linux) binaries. can be both used as a library, or as a standalone executable (`example` project)

## Usage

```sh
zydiff <primary_binary> <secondary_binary>
```

## Example

```cpp
#include "core/differ.h"

binary_differ differ("old_binary", "new_binary");
const auto result = differ.compare();

for (const auto& function : result.matches) {
  const auto blocks = binary_differ::diff_blocks(function);
  if (!blocks) {
    continue;
  }
  for (const auto& block : *blocks) {
    for (const auto& instruction : block.instructions) {
      switch (instruction.type) {
        case binary_differ::edit_type::unchanged:
        case binary_differ::edit_type::changed:
        case binary_differ::edit_type::added:
        case binary_differ::edit_type::removed:
          break;
      }
    }
  }
}
```
