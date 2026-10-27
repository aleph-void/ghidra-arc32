# ARC32 (legacy 32-bit ARC) processor module for Ghidra

Ghidra support for the legacy, pre-ARCompact ARC instruction set with 32-bit instructions
("ARC" in GNU binutils and GCC; ARCtangent-A4 and the earlier ARC basecase cores). It was used,
for example, in the Intel Management Engine of chipsets before the Intel 5 Series and in the
Broadcom Crystal HD video decoder.

It was written by cyrozap as Ghidra pull request
[#3233](https://github.com/NationalSecurityAgency/ghidra/pull/3233), which named the language
"ARC32" to avoid confusion with the later ARC instruction sets. This copy is the Ghidra-Rare
fork, which tested it against GNU binutils 2.25.1 (the last release with this target), the
ARCtangent-A4 Programmer's Reference and code compiled with GCC 4.5.4, and fixed what the tests
found; see [GHIDRA-RARE.md](GHIDRA-RARE.md) for the results and [CREDITS.md](CREDITS.md) for the
authors and the list of changes. ARCompact (ARC600/ARC700) and ARCv2 (ARC EM/HS) are different
instruction sets and are not covered here.

## Install

Download the zip for your Ghidra version from this repository's Releases page (built for
Ghidra 12.1.3, 12.1.4 and 12.2) and install it with *File > Install Extensions*. To build it
yourself: `GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension`.

## Languages

| Language ID | Description | ELF auto-select |
|---|---|---|
| `ARC32:LE:32:default` | legacy ARC, little-endian | e_machine 45 (EM_ARC), ELF32 LSB |
| `ARC32:BE:32:default` | legacy ARC, big-endian | e_machine 45, ELF32 MSB |

## Known limitations

These were collected from the pull request description and discussion, the TODO/FIXME comments
of its files, the review of the alternative implementation in pull request #6344, and
Ghidra-Rare's own testing.

| Limitation | Status |
|---|---|
| MAX, MIN and NORM not implemented (TODOs) | **Fixed**: `max`, `min`, `norm` (and `swap`, `mul64`/`mulu64`, `rrc`) decode and have p-code, checked in the emulator |
| No semantics for LP zero-overhead loops (FIXME) | **Fixed**: `lp` marks the loop end through context and the loop-end instruction branches back to the loop start while `lp_count` is not exhausted; loops set up by writing `lp_start`/`lp_end` with `sr` (as GCC does) are marked by an analyzer |
| "Only execute the delay slot when jumping" (`.jd`) not implemented (FIXME) | **Fixed**: ND, D and JD delay-slot modes for `b`, `bl`, `lp`, `j`, `jl` |
| `.f`/flag semantics "guessed" (FIXME) and add/sub/adc/sbc flags | **Fixed**: flag code rewritten from the manual and checked in the emulator |
| DWARF register mappings guessed (FIXME) | **Fixed/confirmed** against GCC 4.5.4's DWARF output |
| No automated tests of the disassembly or p-code (pull request description) | **Fixed**: decode differential against binutils 2.25.1, every-entry test, emulator tests and real-code tests (`test/run-tests.sh`) |
| GCC 4.5.4 could not be built | **Done**: built as a 32-bit-host cross compiler; it compiles the real-code samples (`test/build-real-samples.sh`) |
| Directory named `ARC` for all ARC variants (pull request discussion) | Kept as `ARC32` only; ARCompact is a separate module (Ghidra-Rare `ARCompact`) |

Remaining gaps found by testing are listed in [GHIDRA-RARE.md](GHIDRA-RARE.md).
