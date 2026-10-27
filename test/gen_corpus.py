#!/usr/bin/env python3
"""Decode-test corpora for the legacy ARC (ARC32) module: 8-byte slots (instruction word and a
long-immediate word), written in both byte orders.

  gen_corpus.py <outdir>
  -> fields_{le,be}.bin  every major opcode with special register-field values (0, 1, 2, 26, 29,
                         31, 32, 59, 60 and the immediate indicators 61-63) in A, B and C, and
                         five fillings of bits 8..0
     low_{le,be}.bin     every value of bits 8..0 (condition, flag, delay mode, short immediate,
                         load/store bits) for each major opcode with C in {3, 61, 62, 63}, and for
                         major 0x03 every sub-opcode C with B in {2, 61, 62, 63}; every value of
                         the load/store mode fields; add/adc/and with B = C for every register
     fuzz_{le,be}.bin    50,000 random slots
The encodings are generated from the field layout of the ARCtangent-A4 Programmer's Reference;
nothing is taken from binutils.
"""
import os
import random
import struct
import sys

out = sys.argv[1]
R = random.Random(20261026)
SPEC = [0, 1, 2, 26, 29, 31, 32, 59, 60, 61, 62, 63]


def w(I, A, B, C, low):
    return (I << 27) | (A << 21) | (B << 15) | (C << 9) | (low & 0x1ff)


def save(name, words):
    for e, fmt in (("le", "<II"), ("be", ">II")):
        with open(os.path.join(out, f"{name}_{e}.bin"), "wb") as f:
            for ins, limm in words:
                f.write(struct.pack(fmt, ins, limm))


def limm():
    return R.choice([0x12345678, 0x00000100, 0x80000100, 0xfffffffc, R.getrandbits(32)])


fields = []
for I in range(32):
    for A in SPEC:
        for B in SPEC:
            for C in SPEC:
                for low in (0, 0x1ff, 0x100, R.getrandbits(9), R.getrandbits(9)):
                    fields.append((w(I, A, B, C, low), limm()))
save("fields", fields)

low = []
for I in range(32):
    for C in (3, 61, 62, 63):
        for d in range(512):
            low.append((w(I, 1, (2, 31, 61, 63)[d % 4], C, d), limm()))
for C in range(64):
    for B in (2, 61, 62, 63):
        for d in range(512):
            low.append((w(3, R.choice([1, 61, 62, 63]), B, C, d), limm()))
for I in (0, 1, 2):
    for A in range(64):
        for C in range(64):
            for B in (2, 31, 61, 62, 63):
                low.append((w(I, A, B, C, R.getrandbits(9)), limm()))
for I in (8, 9, 12):                  # equal B and C fields (asl/rlc/mov aliases)
    for k in range(64):
        low.append((w(I, 1, k, k, R.getrandbits(9)), limm()))
save("low", low)

fuzz = [(R.getrandbits(32), R.getrandbits(32)) for _ in range(50000)]
save("fuzz", fuzz)
print(len(fields), len(low), len(fuzz))
