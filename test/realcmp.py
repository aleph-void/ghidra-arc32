#!/usr/bin/env python3
"""Compare a Ghidra analysis listing (RealCheck.java) with GNU libopcodes at the same addresses.

  realcmp.py <file.elf> <ghidra.lst> <slotdis> <outdir> [--delta N]

For every instruction Ghidra found in an executable PT_LOAD segment, slotdis disassembles the
bytes of the ELF file at that address (slotdis25 -l mode, libopcodes 2.25.1), and compare.py
scores the two (same normalisation as the decode corpora). --delta is the amount
Ghidra relocated the image by (image base of a shared object linked at 0).
"""
import os
import struct
import subprocess
import sys

elf, lst, slotdis, out = sys.argv[1:5]
delta = int(sys.argv[sys.argv.index("--delta") + 1], 0) if "--delta" in sys.argv else 0
here = os.path.dirname(os.path.abspath(__file__))
data = open(elf, "rb").read()
e = "<" if data[5] == 1 else ">"
phoff, = struct.unpack_from(e + "I", data, 0x1c)
phentsize, phnum = struct.unpack_from(e + "HH", data, 0x2a)
segs = []
for i in range(phnum):
    p_type, p_off, p_vaddr, _, p_filesz, _, p_flags, _ = struct.unpack_from(e + "8I", data, phoff + i * phentsize)
    if p_type == 1 and p_flags & 1:
        segs.append((p_vaddr, p_off, p_filesz))
g = {}
for line in open(lst):
    a, hx, txt = line.rstrip("\n").split(" ", 2)
    g[int(a, 16) - delta] = (len(hx) // 2, txt)
gout = open(f"{out}.g", "w")
oout = open(f"{out}.o", "w")
for vaddr, off, size in segs:
    addrs = sorted(a for a in g if vaddr <= a < vaddr + size)
    if not addrs:
        continue
    raw = f"{out}.seg"
    open(raw, "wb").write(data[off:off + size])
    open(f"{out}.addrs", "w").write("".join(f"{a:x}\n" for a in addrs))
    r = subprocess.run([slotdis, "8", raw, "-l", f"{out}.addrs", "-b", f"{vaddr:x}",
                        "-e", "little" if e == "<" else "big"], capture_output=True, text=True, check=True)
    oout.write(r.stdout)
    for a in addrs:
        gout.write(f"{a:08x} {g[a][0]} {g[a][1]}\n")
    os.remove(raw)
    os.remove(f"{out}.addrs")
gout.close()
oout.close()
sys.exit(subprocess.run([sys.executable, os.path.join(here, "compare.py"), f"{out}.g", f"{out}.o"]).returncode)
