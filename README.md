# zydiff

This is a small binary diffing tool that uses Zydis for disassembly.
It's not particularly fast or smart, but it might be useful.

Right now it only handles PE files and .text section diffing.
The matching is pretty basic and slow - O(n^2) because I'm lazy