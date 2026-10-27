#!/usr/bin/env python3
"""Score Ghidra's decoding (DumpSlots.java) against libopcodes 2.25.1 (slotdis25) for the legacy
ARC (ARC32) module and bucket every difference.

  compare.py <ghidra.txt> <objdump.txt> [--list N]

Both inputs: "<offset-hex> <len> <text>" per slot (Ghidra "BAD", objdump "(bad)" when rejected;
slotdis25 prints the instruction word before the text, which is dropped here).

Exact: identical text after collapsing blanks. Semantic: identical after these spellings are
normalised: numbers (objdump decimal or 0x1234_5678, Ghidra hex) compared as 32-bit values,
branch targets modulo 2^26 (the program counter is 26 bits; objdump prints 64-bit negative
addresses). Other differences go to named classes; "UNEXPLAINED" must stay empty.
"""
import re
import sys
from collections import Counter, defaultdict

EXT_MAJ = {"ext%02x" % i for i in range(0x16, 0x1e)}
EXT_OPT = {"asl", "lsr", "asr", "ror", "mul64", "mulu64", "max", "min"}  # majors 0x10-0x15, 0x1e-0x1f
EXT_SOP = {"swap", "norm"} | {"extsop%02x" % i for i in range(0x0b, 0x3f)}
BRANCH = re.compile(r"^(b|bl|lp|j|jl)[a-z0-9]*$")


def load(path, strip_word):
    res = {}
    for line in open(path):
        line = line.rstrip("\n")
        parts = line.split(" ", 2)
        off = int(parts[0], 16)
        n = int(parts[1])
        text = parts[2] if len(parts) > 2 else ""
        if strip_word:
            t = text.split(None, 1)
            # slotdis25 output: "<word> <text>"; an empty text (word 0) stays empty
            text = t[1] if len(t) > 1 else ""
            if n == 0:
                text = "(bad)"
        if not strip_word and text.startswith("_"):
            text = text[1:]  # Ghidra marks an instruction in a delay slot with a leading "_"
        res[off] = (n, " ".join(text.split()))
    return res


def num(tok):
    tok = tok.replace("_", "")
    try:
        return int(tok, 0) & 0xffffffff
    except ValueError:
        return None


def canon(text):
    """Split into mnemonic parts and operand tokens with numbers as values."""
    if not text:
        return None
    m = text.split(" ", 1)
    mn = m[0]
    ops = m[1] if len(m) > 1 else ""
    toks = re.findall(r"[A-Za-z_][A-Za-z_0-9]*|-?0x[0-9a-fA-F_]+|-?[0-9]+|[\[\],]", ops)
    out = []
    for t in toks:
        v = num(t) if re.match(r"-?[0-9]", t) else None
        out.append(v if v is not None else t)
    return mn, out


def is_branch(mn):
    base = mn.split(".")[0]
    return bool(BRANCH.match(base))


def norm_targets(mn, ops):
    if is_branch(mn):
        return [o & 0x3ffffff if isinstance(o, int) else o for o in ops]
    return ops


def classify(g, o):
    """Return (class, detail) for a slot. Class 'exact'/'semantic' are agreements."""
    gn, gt = g
    on, ot = o
    gbad = gt == "BAD"
    obad = ot == "(bad)"
    if gbad and obad:
        return "both-invalid"
    if gbad:
        if "(0[3])" in ot or "(1[3])" in ot or "(2[3])" in ot:
            return "reserved load/store size 3: objdump prints ???, Ghidra rejects"
        if ot.split(" ")[0].startswith("???") and ot.split(" ")[0].split(".")[0] == "???":
            return "objdump ??? / Ghidra rejects"
        return "UNEXPLAINED ghidra-bad"
    if obad:
        return "UNEXPLAINED objdump-bad"
    if gt == ot:
        return "exact"
    if ot == "":
        if gt.startswith("ld r0,[r0,r0]"):
            return "objdump prints nothing for the all-zero word (ld r0,[r0,r0])"
        return "UNEXPLAINED objdump-empty"
    cg, co = canon(gt), canon(ot)
    gmn, gops = cg
    omn, oops = co
    gops = norm_targets(gmn, gops)
    oops = norm_targets(gmn, oops)
    if gn != on:
        return "UNEXPLAINED length"
    if gmn == omn and gops == oops:
        return "semantic"
    gp = gmn.split(".")
    op = omn.split(".")
    # objdump's "???" stands for an extension opcode or condition it has no name for
    if "???" in omn or omn.startswith("b???") or omn.startswith("bl???") or omn.startswith("lp???") or \
            omn.startswith("j???") or omn.startswith("jl???"):
        ok = gops == oops and len(gp) == len(op)
        if ok:
            for a, b in zip(gp, op):
                if a == b:
                    continue
                if b == "???" and (a in EXT_MAJ or a in EXT_OPT or a in EXT_SOP or re.match(r"x1[0-9a-f]$", a)):
                    continue
                if b.endswith("???") and re.match(r"^(b|bl|lp|j|jl)x1[0-9a-f]$", a) and a.startswith(b[:-3]):
                    continue
                ok = False
                break
        if ok:
            kinds = set()
            if gp[0] in EXT_OPT:
                kinds.add("optional extension instruction (manual)")
            elif gp[0] in EXT_SOP:
                kinds.add("optional/extension single-operand instruction")
            elif gp[0] in EXT_MAJ:
                kinds.add("user extension major 0x16-0x1d")
            if any(re.match(r"(.*)x1[0-9a-f]$", p) for p in gp):
                kinds.add("extension condition 0x10-0x1f")
            return "objdump ??? (no name): " + " + ".join(sorted(kinds))
        return "UNEXPLAINED ???"
    return "UNEXPLAINED"


def main():
    g = load(sys.argv[1], False)
    o = load(sys.argv[2], True)
    nlist = int(sys.argv[sys.argv.index("--list") + 1]) if "--list" in sys.argv else 5
    cls = Counter()
    ex = defaultdict(list)
    for off in sorted(g):
        c = classify(g[off], o[off])
        cls[c] += 1
        if len(ex[c]) < nlist:
            ex[c].append("%08x | %s | %s" % (off, g[off][1], o[off][1]))
    total = sum(cls.values())
    both = total - cls["both-invalid"]
    agree = cls["exact"] + cls["semantic"]
    unexpl = sum(v for k, v in cls.items() if k.startswith("UNEXPLAINED"))
    explained = both - agree - unexpl
    print("slots %d, decoded by either %d: exact %d (%.2f%%), semantic %d (%.2f%%), explained %d, "
          "unexplained %d, both invalid %d" % (total, both, cls["exact"], 100.0 * cls["exact"] / max(both, 1),
                                               agree, 100.0 * agree / max(both, 1), explained, unexpl,
                                               cls["both-invalid"]))
    for k, v in cls.most_common():
        print("%8d  %s" % (v, k))
        if k not in ("exact", "semantic", "both-invalid"):
            for e in ex[k]:
                print("            " + e)
    return 1 if unexpl else 0


if __name__ == "__main__":
    sys.exit(main())
