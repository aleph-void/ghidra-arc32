#!/usr/bin/env python3
"""P-code semantic tests for Ghidra's emulator (EmuCheck.java), assembled with GNU as 2.25.1
(arc-elf, the legacy ARC target).

  emu_tests.py <outdir> <bin-prefix> [--break N]
      <bin-prefix>: binutils prefix, e.g. .../bin/arc-elf- (needs as, ld, objcopy, nm)
  -> emu_{le,be}.bin and emu_{le,be}.txt

Each test is a short sequence at its own 0x100-aligned address followed by a "stop" label. The
.txt files have one line per test:
  <name> <start-hex> <stop-hex> <init: reg=val,...|-> <expect: reg=val,...>
Values are hex. A data area at 0x8000 (D0 below) is part of the image. The expected values are
worked out by hand from the ARCtangent-A4 Programmer's Reference. Optional instructions that
the assembler does not know (barrel shifter, multiplier, MIN/MAX, SWAP, NORM) are written as
.word with the encodings of that manual.
--break N makes the expectation of test N wrong (to show that the check can fail).
"""
import os
import re
import subprocess
import sys

out, pre = sys.argv[1], sys.argv[2]
brk = int(sys.argv[sys.argv.index("--break") + 1]) if "--break" in sys.argv else -1
M = 0xffffffff

# data area at 0x8000: 16 bytes 00 01 02 ... 0f, then 0x80 0xff 0x7f 0x00, then zeros
D0 = bytes(range(16)) + bytes([0x80, 0xff, 0x7f, 0x00]) + bytes(44)


def word(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 4]
    return int.from_bytes(b, "little" if e == "le" else "big")


def half(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 2]
    return int.from_bytes(b, "little" if e == "le" else "big")


def enc(I, A, B, C, low=0):
    """Instruction word (manual, "Instruction Encoding"): I[31:27] A[26:21] B[20:15] C[14:9]."""
    return f" .word {(I << 27) | (A << 21) | (B << 15) | (C << 9) | (low & 0x1ff):#010x}"


def status(pc, Z=0, N=0, C=0, V=0, E2=0, E1=0, H=0):
    """STATUS register value: Z N C V E2 E1 H in bits 31..25, PC[25:2] in bits 23..0."""
    return (Z << 31) | (N << 30) | (C << 29) | (V << 28) | (E2 << 27) | (E1 << 26) | (H << 25) | \
        ((pc >> 2) & 0xffffff)


# (name, asm, init, expect); expect may be a function of the byte order and of the symbol table
T = [
    ("add", "add r0,r1,r2", {"r1": 5, "r2": 7}, {"r0": 12}),
    ("add.f_carry", "add.f r0,r1,r2", {"r1": M, "r2": 1}, {"r0": 0, "Z": 1, "N": 0, "C": 1, "V": 0}),
    ("add.f_overflow", "add.f r0,r1,r2", {"r1": 0x7fffffff, "r2": 1},
     {"r0": 0x80000000, "Z": 0, "N": 1, "C": 0, "V": 1}),
    ("add_no_flags", "add r0,r1,r2", {"r1": M, "r2": 1, "Z": 0, "C": 0}, {"r0": 0, "Z": 0, "C": 0}),
    ("sub.f_borrow", "sub.f r0,r1,r2", {"r1": 1, "r2": 2}, {"r0": M, "Z": 0, "N": 1, "C": 1, "V": 0}),
    ("sub.f_overflow", "sub.f r0,r1,r2", {"r1": 0x80000000, "r2": 1},
     {"r0": 0x7fffffff, "N": 0, "C": 0, "V": 1}),
    ("adc", "add.f r0,r1,r2\n adc r3,r4,r5\n adc.f r6,r4,r5", {"r1": M, "r2": 1, "r4": 0x10, "r5": 0x20},
     {"r0": 0, "r3": 0x31, "r6": 0x31, "C": 0}),
    ("adc.f_carry_in_out", "adc.f r3,r1,r2", {"r1": M, "r2": 0, "C": 1}, {"r3": 0, "C": 1, "Z": 1, "V": 0}),
    ("sbc", "sub.f r0,r1,r2\n sbc.f r3,r4,r4", {"r1": 1, "r2": 2, "r4": 5}, {"r3": M, "C": 1, "N": 1, "Z": 0}),
    ("logic", "and r3,r1,r2\n or r4,r1,r2\n xor r5,r1,r2\n bic r6,r1,r2\n mov r7,r1",
     {"r1": 0xf0f0, "r2": 0xff00}, {"r3": 0xf000, "r4": 0xfff0, "r5": 0x0ff0, "r6": 0x00f0, "r7": 0xf0f0}),
    ("logic_flags", "and.f r3,r1,r2\n or.f 0,r1,r1", {"r1": 0x80000000, "r2": 0x7fffffff, "C": 1, "V": 1},
     {"r3": 0, "Z": 0, "N": 1, "C": 1, "V": 1}),
    ("shimm_limm", "add r0,r1,-5\n mov r2,0x12345678\n add r3,r2,0x11111111\n add r4,0x10,r2\n sub r5,100,r1",
     {"r1": 3}, {"r0": M - 1, "r2": 0x12345678, "r3": 0x23456789, "r4": 0x12345688, "r5": 97}),
    ("shimm_flags", "add.f r0,r1,-3", {"r1": 3}, {"r0": 0, "Z": 1, "C": 1}),
    ("cond_exec", "sub.f 0,r1,r2\n mov.z r3,1\n mov.nz r4,1\n add.ge r5,r5,1\n add.lt r6,r6,1",
     {"r1": 5, "r2": 5}, {"r3": 1, "r4": 0, "r5": 1, "r6": 0, "Z": 1}),
    ("cond_signed", "sub.f 0,r1,r2\n mov.gt r3,1\n mov.lt r4,1\n mov.hi r5,1\n mov.ls r6,1",
     {"r1": M, "r2": 1}, {"r3": 0, "r4": 1, "r5": 1, "r6": 0}),
    ("single_shifts", "asl.f r3,r1\n lsr r4,r1\n asr.f r5,r1\n ror r6,r1", {"r1": 0x80000001},
     {"r3": 2, "r4": 0x40000000, "r5": 0xc0000000, "r6": 0xc0000000, "C": 1, "N": 1, "V": 1}),
    ("asl_overflow", "asl.f r3,r1", {"r1": 0x40000000}, {"r3": 0x80000000, "V": 1, "N": 1, "C": 0}),
    ("rotate_carry", "add.f 0,r1,r1\n rrc r3,r2\n rlc.f r4,r2", {"r1": 0x80000000, "r2": 2},
     {"r3": 0x80000001, "r4": 5, "C": 0}),
    ("extend", "sexb r2,r1\n sexw r3,r1\n extb r4,r1\n extw.f r5,r1", {"r1": 0x80ff},
     {"r2": M, "r3": 0xffff80ff, "r4": 0xff, "r5": 0x80ff, "N": 0, "Z": 0}),
    # barrel shifter (0x10-0x13): asl r3,r1,4 / lsr r4,r1,r2 / asr r5,r1,4 / ror r6,r1,4 / asl.f r7,r1,36
    ("barrel", "\n".join([enc(0x10, 3, 1, 63, 4), enc(0x11, 4, 1, 2), enc(0x12, 5, 1, 63, 4),
                          enc(0x13, 6, 1, 63, 4), enc(0x10, 7, 1, 61, 4)]),
     {"r1": 0x80000011, "r2": 4},
     {"r3": 0x110, "r4": 0x08000001, "r5": 0xf8000001, "r6": 0x18000001, "r7": 0x110, "N": 0, "Z": 0}),
    # mul64 0,r1,r2 / mulu64 0,r1,r2
    ("mul64", enc(0x14, 63, 1, 2) + "\n mov r3,r57\n mov r4,r58\n mov r5,r59",
     {"r1": 0xfffffffe, "r2": 0x30000}, {"r3": 0xfffa0000, "r4": 0xfffffffa, "r5": M}),
    ("mulu64", enc(0x15, 63, 1, 2) + "\n mov r3,r57\n mov r4,r58\n mov r5,r59",
     {"r1": 0xfffffffe, "r2": 0x30000}, {"r3": 0xfffa0000, "r4": 0xfffffffa, "r5": 0x2ffff}),
    # max.f r3,r1,r2 / min r4,r1,r2
    ("max_min", enc(0x1e, 3, 1, 2, 0x100) + "\n" + enc(0x1f, 4, 1, 2),
     {"r1": 0xfffffffb, "r2": 3}, {"r3": 3, "r4": 0xfffffffb, "C": 1, "N": 1, "Z": 0, "V": 0}),
    # swap r3,r1 / norm r4,r1 / norm r5,r2 / norm r6,r6 / norm.f r7,r8
    ("swap_norm", "\n".join([enc(3, 3, 1, 9), enc(3, 4, 1, 10), enc(3, 5, 2, 10), enc(3, 6, 6, 10),
                             enc(3, 7, 8, 10, 0x100)]),
     {"r1": 0x12345678, "r2": 0xe0000000, "r6": 0, "r8": 0x3fffffff},
     {"r3": 0x56781234, "r4": 2, "r5": 2, "r6": 31, "r7": 1, "Z": 0}),
    ("load_modes", "mov r1,0x8000\n ld r3,[r1,4]\n ldb r4,[r1,5]\n ldw r5,[r1,6]\n ld r6,[r1,r2]\n ld r7,[0x8008]",
     {"r2": 0xc}, lambda e, s: {"r3": word(0x8004, e), "r4": 5, "r5": half(0x8006, e),
                                "r6": word(0x800c, e), "r7": word(0x8008, e)}),
    ("load_sign_extend", "mov r1,0x8010\n ldb.x r3,[r1,0]\n ldb r4,[r1,0]\n ldw.x r5,[r1,0]\n ldw.x r6,[r1,r2]",
     {"r2": 2}, lambda e, s: {"r3": 0xffffff80, "r4": 0x80, "r5": 0xffffff80 if e == "le" else 0xffff80ff,
                              "r6": 0x7f if e == "le" else 0x7f00}),
    ("load_writeback", "mov r1,0x8000\n ld.a r3,[r1,4]\n ldb.a r4,[r1,r2]", {"r2": 2},
     lambda e, s: {"r1": 0x8006, "r3": word(0x8004, e), "r4": 6}),
    ("store_modes", "mov r1,0x8020\n st 0x12345678,[r1,4]\n stb r2,[r1,8]\n stw r2,[r1,12]\n"
     " stb -2,[r1,18]\n st.a r3,[r1,20]\n ld r4,[0x8024]\n ld r5,[0x8028]\n ld r6,[0x802c]\n"
     " ld r7,[0x8034]\n ldb r8,[0x8032]",
     {"r2": 0xaabbccdd, "r3": 0x55},
     lambda e, s: {"r1": 0x8034, "r4": 0x12345678, "r5": 0xdd if e == "le" else 0xdd000000,
                   "r6": 0xccdd if e == "le" else 0xccdd0000, "r7": 0x55, "r8": 0xfe}),
    ("branch_nd", "b 1f\n mov r1,1\n mov r2,1\n1: mov r3,1", {}, {"r1": 0, "r2": 0, "r3": 1}),
    ("branch_d", "b.d 1f\n mov r1,1\n mov r2,1\n1: mov r3,1", {}, {"r1": 1, "r2": 0, "r3": 1}),
    ("branch_cond", "sub.f 0,r0,r0\n bnz 1f\n mov r1,1\n bz.jd 1f\n mov r2,1\n mov r4,1\n1: mov r3,1",
     {}, {"r1": 1, "r2": 1, "r3": 1, "r4": 0}),
    ("branch_jd_not_taken", "sub.f 0,r0,r0\n bnz.jd 1f\n mov r1,1\n mov r2,1\n1: mov r3,1",
     {}, {"r1": 0, "r2": 1, "r3": 1}),
    ("bl_link_return", "bl 2f\n mov r5,1\n b 3f\n2: mov r4,blink\n j [blink]\n3: nop",
     {"Z": 1, "C": 1}, lambda e, s: {"r4": status(s["T"] + 4, Z=1, C=1), "r5": 1}),
    ("bl.d_link", "bl.d 2f\n mov r6,1\n mov r5,1\n b 3f\n2: mov r4,blink\n j.d [blink]\n mov r7,1\n3: nop",
     {}, lambda e, s: {"r4": status(s["T"] + 8), "r5": 1, "r6": 1, "r7": 1}),
    ("jl_register", "mov r1,2f\n lsr r1,r1\n lsr r1,r1\n jl [r1]\n mov r5,1\n b 3f\n2: mov r4,blink\n j [blink]\n3: nop",
     {}, lambda e, s: {"r4": status(s["T"] + 20), "r5": 1}),
    ("jl_limm", "jl 2f\n mov r5,1\n b 3f\n2: mov r4,blink\n j [blink]\n3: nop",
     {}, lambda e, s: {"r4": status(s["T"] + 8), "r5": 1}),
    ("j.f_flags", "mov r1,1f\n lsr r1,r1\n lsr r1,r1\n or r1,r1,0x20000000\n j.f [r1]\n mov r2,1\n1: mov r3,1",
     {"N": 1, "V": 1}, {"r2": 0, "r3": 1, "Z": 0, "N": 0, "C": 1, "V": 0}),
    ("lp_loop", "mov lp_count,3\n lp 1f\n add r0,r0,1\n add r1,r1,2\n1: add r2,r2,1",
     {}, {"r0": 3, "r1": 6, "r2": 1, "lp_count": 0}),
    ("lp_not_taken", "sub.f 0,r0,r0\n lpnz 1f\n add r0,r0,1\n add r1,r1,2\n1: add r2,r2,1",
     {}, {"r0": 0, "r1": 0, "r2": 1}),
    ("flag", "flag 0x7e", {}, {"Z": 1, "N": 1, "C": 1, "V": 1, "E2": 1, "E1": 1, "H": 0}),
    ("flag_halt_keeps", "flag 0x41", {"N": 1}, {"Z": 0, "N": 1, "H": 1}),
    ("aux_regs", "sr r1,[0x10]\n lr r2,[0x10]\n lr r3,[status]\n mov r4,1f\n1: nop",
     {"r1": 0x1234, "C": 1}, lambda e, s: {"r2": 0x1234, "r3": status(s["T"] + 12, C=1)}),
]


def build(e):
    src = [" .text"]
    for i, (name, asm, _, _) in enumerate(T):
        src.append(f" .org {i * 0x100:#x}\nT{i}: {asm}\nS{i}: nop\n")
    src.append(" .org 0x8000\n .byte " + ",".join(str(b) for b in D0))
    base = f"{out}/emu_{e}"
    open(base + ".s", "w").write("\n".join(src) + "\n")
    eb = ["-EB"] if e == "be" else []
    subprocess.run([pre + "as"] + eb + [base + ".s", "-o", base + ".o"], check=True)
    subprocess.run([pre + "ld"] + eb + ["-Ttext=0", "-e", "0", base + ".o", "-o", base + ".elf"], check=True)
    subprocess.run([pre + "objcopy", "-O", "binary", base + ".elf", base + ".bin"], check=True)
    syms = {}
    for line in subprocess.run([pre + "nm", base + ".elf"], capture_output=True, text=True).stdout.split("\n"):
        m = re.match(r"([0-9a-f]+) \w (\w+)$", line)
        if m:
            syms[m.group(2)] = int(m.group(1), 16)
    with open(base + ".txt", "w") as f:
        for i, (name, _, init, exp) in enumerate(T):
            exp = exp(e, {"T": syms["T%d" % i]}) if callable(exp) else dict(exp)
            if i == brk:
                r = next(iter(exp))
                exp[r] ^= 1
            ini = ",".join(f"{r}={v & M:x}" for r, v in init.items()) or "-"
            f.write(f"{name} {syms['T%d' % i]:x} {syms['S%d' % i]:x} {ini} "
                    + ",".join(f"{r}={v & M:x}" for r, v in exp.items()) + "\n")
    for x in (".o", ".elf"):
        os.remove(base + x)


for e in ("le", "be"):
    build(e)
print(f"{len(T)} tests")
