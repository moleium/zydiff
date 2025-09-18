# zydiff

A lightweight binary diffing library for x86-64 executables.

zydiff compares two binaries and generates a diff of the changes. using the Zydis disassembler engine.
Supports both PE (Windows) and ELF (Linux) binaries. can be both used as a library, or as a standalone executable (`example` project)

## Usage

```sh
zydiff <primary_binary> <secondary_binary>
```
