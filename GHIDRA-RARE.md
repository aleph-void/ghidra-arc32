# Ghidra-Rare notes: ARC32 (legacy 32-bit ARC, ARCtangent-A4)

This is the Ghidra-Rare fork of Ghidra pull request
[#3233](https://github.com/NationalSecurityAgency/ghidra/pull/3233) (32-bit legacy ARC support by
cyrozap). Ghidra-Rare tested it against GNU binutils 2.25.1 (the last release with this target),
the ARCtangent-A4 Programmer's Reference and code compiled with GCC 4.5.4 (the last GCC with
this target), and fixed what the tests found. Authors, upstream commit and the list of changes
are in [CREDITS.md](CREDITS.md); the upstream limitations and their status are in
[README.md](README.md). It targets Ghidra 12.1.4 and also builds on 12.1.3 and 12.2; prebuilt
zips are on the fork's Releases page.

Ghidra pull request #6344 ("ARC4", Dan Genin) implements the same ARCtangent-A4 instruction set
(it is not ARCv2); it was compared with this module and credited, see CREDITS.md.

## What it covers

| Language ID | Description |
|---|---|
| `ARC32:LE:32:default` | legacy ARC (ARCtangent-A4 and earlier basecase cores), little-endian |
| `ARC32:BE:32:default` | the same, big-endian |

- Every instruction of the ARCtangent-A4 Programmer's Reference: the basecase ALU, single-operand
  and load/store instructions with short and long immediates, all condition codes, the three
  delay-slot modes, `lp` zero-overhead loops, `lr`/`sr`, `flag`, `brk`/`sleep`/`swi`, and the
  optional barrel shifter (`asl`/`asr`/`lsr`/`ror` a,b,c), `mul64`/`mulu64`, `max`/`min`,
  `swap` and `norm`. User extension majors 0x16-0x1d and unused single-operand sub-opcodes decode
  as `extNN` / `extsopNN` (core-specific extension instructions), extension condition codes
  0x10-0x1f as `.x10` ... `.x1f`.
- Syntax: GNU objdump 2.25.1's (`mov`/`asl`/`rlc` aliases, `0` for a discarded result,
  `[b,c]`/`[b,s9]` addresses, `.a`/`.x`/`.di`, aux register names in `lr`/`sr`).
- Semantics: real p-code for everything above, including flags, `bl`/`jl` links in STATUS
  format, `j.f`, delay slots and loops. Named pcodeops: `brk`, `sleep`, `swi`, the extension
  instructions and extension condition codes (customer-defined hardware).
- Spec files: GCC calling convention (cspec), DWARF register map, ELF opinion (e_machine 45),
  pspec with the auxiliary register names. Two analyzers (Java): loops set up with `sr` to
  `lp_start`/`lp_end`, and indirect calls written as `j.d [reg]` with `add blink,blink,2` in the
  delay slot.

## Testing

Requirements: Ghidra (`GHIDRA_INSTALL_DIR`, with this directory as `Ghidra/Processors/ARC32`),
GNU binutils 2.25.1 configured `--target=arc-elf` (its build tree for `test/slotdis25.c`, a small
libopcodes driver, and the installed `arc-elf-as`/`ld` for the emulator tests) and, for the
real-code tests, GCC 4.5.4 for arc-elf. GCC 4.5.4 crashes ("unrecognizable insn") when it is
built as a 64-bit host program; build it as a 32-bit (i686) host program.

```
test/run-tests.sh [workdir]           # SLEIGH compile, decode diff, every-entry test, emulator tests
test/run-tests.sh --real [workdir]    # ... plus building and analysing the real-code samples
```

See the header of `test/run-tests.sh` for the environment variables (`SLOTDIS25` or `BU25`/
`BU25_SRC`, `ARC_TOOLS`, `ARC_GCC`, `LIBGCC_LE`/`LIBGCC_BE`). `test/env.sh` points Ghidra at a
private settings directory, because the headless script runner takes a user-wide lock.

## Results

### Decoding vs GNU libopcodes 2.25.1

`test/gen_corpus.py` writes three corpora per byte order, in 8-byte slots (instruction word and
a long immediate), generated from the manual's field layout: `fields` (every major opcode with
special register-field values 0, 1, 2, 26, 29, 31, 32, 59, 60, 61, 62, 63 in A, B and C and five
fillings of bits 8..0; 276,480 slots), `low` (every value of bits 8..0 per major opcode and
special C values, every single-operand sub-opcode, every load/store mode, add/adc/and with B = C
for every register; 258,240) and `fuzz` (50,000 random slots). Ghidra (`DumpSlots.java`) and
libopcodes (`slotdis25`) decode the first instruction of each slot; `test/compare.py` scores them.

| Corpus | Slots | Exact | Semantic | Explained | Unexplained |
|---|---|---|---|---|---|
| fields LE / BE | 276,480 | 42,722 | 96,278 | 180,202 | 0 |
| low LE / BE | 258,240 | 27,430 | 90,139 | 168,101 | 0 |
| fuzz LE / BE | 50,000 | 8,903 | 13,655 | 36,345 | 0 |

"Semantic" allows number spellings (objdump decimal or `0x1234_5678`, Ghidra hex) and branch
targets modulo 2^26 (the program counter is 26 bits). The explained classes are almost all
words objdump prints as `???` because 2.25.1 knows no name for them:

| Class | Why |
|---|---|
| user extension majors 0x16-0x1d (`extNN` in Ghidra) | customer-defined extension instructions |
| optional instructions of majors 0x10-0x15, 0x1e, 0x1f (barrel shifter, `mul64`/`mulu64`, `max`/`min`) and single-operand `swap`/`norm` | in the manual's optional-extension list; objdump 2.25.1 does not name them |
| extension condition codes 0x10-0x1f (`.x10` ... in Ghidra) | customer-defined conditions |
| unused single-operand sub-opcodes (`extsopNN`) | extension single-operand instructions |
| load/store size 3 and sub-opcodes 0x3d/0x3e (and 0x3f with an unknown function): objdump `???`, Ghidra rejects | reserved by the manual |
| the all-zero word | objdump prints nothing for `ld r0,[r0,r0]` |

**Every-entry test** (`CoverageCheck.java` over the `low` and `fields` corpora plus random
fillings, 4 seeds): all 600 constructors of each language are reached; none is shadowed.

### Emulator

`test/emu_tests.py` assembles 42 short sequences with GNU as 2.25.1 (optional instructions the
assembler does not know are written as `.word` from the manual's encodings) and
`EmuCheck.java` runs them in Ghidra's emulator with hand-computed expectations, in both byte
orders: add/sub/adc/sbc with carry and overflow, flag-less forms, logic and its flags, short
and long immediates and their flag rule, conditional execution (signed and unsigned
conditions), single-bit shifts and `rlc`/`rrc` through carry, `asl` overflow, sign/zero
extension, the barrel shifter, `mul64`/`mulu64`, `max`/`min`, `swap`/`norm`, loads in every
address mode with sign extension and write-back, stores in every mode, `b`/`bl` with ND, D and
JD delay slots (taken and not taken), `bl`/`bl.d`/`jl` links and returns, `jl` to a long
immediate, `j.f` restoring the flags, `lp` loops (taken and skipped), `flag` (including the
halt bit), and `lr`/`sr`. Result: 42/42 per byte order. A deliberately wrong expectation
(`--break 1`) is reported as a failure.

### Real code

`test/build-real-samples.sh` downloads zlib 1.3.1 (zlib license) and Brad Conte's
crypto-algorithms (public domain: AES, DES, Blowfish, MD5, SHA-1, SHA-256) from pinned URLs with
SHA-256 checks and compiles them with GCC 4.5.4 `-O2` for both byte orders, with small
freestanding drivers (`test/real/*.c`, public domain); nothing is committed.
`test/real-binaries.sh` imports each ELF headless without `-processor` (the opinion picks the
language from e_machine 45 and the byte order), analyses it, decompiles every function and
compares every instruction Ghidra found with libopcodes at the same address.

| Sample | Functions | Instructions | Bad instr. | Error bookmarks | Decompiled | Disassembly vs objdump |
|---|---|---|---|---|---|---|
| `zlib-le.elf` | 98 | 15,628 | 0 | 0 | 98 / 98 | 100% (0 unexplained) |
| `zlib-be.elf` | 98 | 15,629 | 0 | 0 | 98 / 98 | 100% |
| `crypto-le.elf` | 59 | 10,726 | 0 | 0 | 59 / 59 | 100% |
| `crypto-be.elf` | 59 | 10,729 | 0 | 0 | 59 / 59 | 100% |

Switch statements are recovered as jump tables (`inflate`). The remaining "Could not recover
jumptable" warnings (2 in zlib, 3 in crypto) are libgcc's division routines, which return
through a copy of `blink` (`mov r7,blink` ... `j [r7]`); the decompiler shows them as an
indirect call and the C is correct.

## Known gaps

- **Extension instructions and extension condition codes** are pcodeops: they are defined by the
  customer's extension hardware.
- **`brk`, `sleep`, `swi`** are pcodeops (debug/power/interrupt hardware) that fall through.
- **Returns through a copy of `blink`** in hand-written assembly (libgcc) decompile as
  "treating indirect jump as call"; the C is correct.
- **Zero-overhead loops set up with `sr`** are marked only when constant propagation finds the
  `lp_start`/`lp_end` values; otherwise the analyzer logs a message and the loop end is not
  marked.
- `lp` loops use `globalset` context, which Ghidra's `EmulatorHelper` honours (tested) and the
  newer `PcodeEmulator` does not (Ghidra issue #9337).

## Unverified

- No freely licensed ARC A4 firmware or binaries from other compilers were found: the Broadcom
  Crystal HD firmware and Intel ME images are not freely licensed and were not used. Real-code
  tests use GCC 4.5.4 output only (which uses no optional instructions).
- Optional instructions (barrel shifter, `mul64`, `max`/`min`, `swap`, `norm`) are checked
  against the manual in the emulator, but no reference disassembler names them.

## Confirmed reference-tool bugs (binutils 2.25.1)

- The legacy ARC disassembler reads uninitialised local variables: the same word can disassemble
  differently from run to run (e.g. the `???` text of extension instructions and the delay-slot
  suffix of `j`/`jl` to a long immediate). The oracle is built with
  `-ftrivial-auto-var-init=zero`, which makes its output deterministic.
- objdump drops the delay-slot suffix of `j`/`jl` with a long immediate when the condition has
  no name, and prints nothing for the all-zero word.
- GCC 4.5.4 built as a 64-bit host program crashes on most input (`extract_insn`); the i686 host
  build works.
