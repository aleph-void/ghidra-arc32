#!/usr/bin/env bash
# ARC32 (legacy ARC, ARCtangent-A4) module tests:
#   1. the generator reproduces data/languages/ARC32_ops.sinc; both .slaspec files compile (and
#      the Java SR-loop analyzer is built into lib/ for a development install)
#   2. decode corpora (test/gen_corpus.py: every major opcode x special register fields, every
#      value of bits 8..0, 50,000 random slots) vs GNU libopcodes 2.25.1, both byte orders
#   3. every-entry decode test (CoverageCheck.java over the corpora, 4 seeds, union)
#   4. p-code emulator tests (EmuCheck.java, both byte orders) and a deliberately broken
#      expectation that must fail
#   5. with --real: build the real-code samples (test/build-real-samples.sh) and run
#      test/real-binaries.sh on them
#
#   test/run-tests.sh [--real] [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x/12.2 whose Ghidra/Processors/ARC32 is (a symlink to) this
#                       module directory
#   BU25                GNU binutils 2.25.1 configured --target=arc-elf: the build directory
#                       (with opcodes/libopcodes.a, bfd/libbfd.a, libiberty/libiberty.a) and its
#                       source tree as BU25_SRC; or SLOTDIS25=<binary built from test/slotdis25.c>.
#                       Build it with CFLAGS=-ftrivial-auto-var-init=zero: the 2.25.1 ARC
#                       disassembler reads uninitialised locals (see GHIDRA-RARE.md).
#   ARC_TOOLS           binutils 2.25.1 prefix for the emulator tests, e.g. .../bin/arc-elf-
#   ARC_GCC             (--real) GCC 4.5.4 arc-elf prefix, e.g. .../bin/arc-elf- ; LIBGCC_LE/BE
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
source "$HERE/env.sh"
REAL=0
if [[ ${1:-} == --real ]]; then REAL=1; shift; fi
: "${ARC_TOOLS:?set ARC_TOOLS}"
W=$(mkdir -p "${1:-arc32-test-work}" && cd "${1:-arc32-test-work}" && pwd)
cd "$W"
rc=0

echo "== compiling SLEIGH"
python3 "$MOD/tools/gen_arc32.py" "$W/ops.sinc"
cmp -s "$W/ops.sinc" "$MOD/data/languages/ARC32_ops.sinc" || { echo "FAIL: ARC32_ops.sinc is not the generator's output"; rc=1; }
for s in "$MOD"/data/languages/*.slaspec; do
	if "$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "ERROR|^Error"; then
		echo "FAIL: $s does not compile"; exit 1
	fi
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'
"$HERE/build-jar.sh"

if [[ -z ${SLOTDIS25:-} ]]; then
	: "${BU25:?set SLOTDIS25, or BU25 and BU25_SRC}" "${BU25_SRC:?set BU25_SRC}"
	SLOTDIS25=$W/slotdis25
	gcc -O2 -w -DPACKAGE=1 -DPACKAGE_VERSION=1 -o "$SLOTDIS25" "$HERE/slotdis25.c" -I"$BU25/bfd" \
		-I"$BU25_SRC/include" "$BU25/opcodes/libopcodes.a" "$BU25/bfd/libbfd.a" \
		"$BU25/libiberty/libiberty.a" -lz -ldl
fi
export SLOTDIS25

echo "== decode corpora vs GNU libopcodes 2.25.1"
python3 "$HERE/gen_corpus.py" .
"$HERE/decode-diff.sh" . || rc=1

echo "== every-entry decode test"
for l in LE BE; do
	e=${l,,}
	cat low_$e.bin fields_$e.bin >cov_$e.bin
	for seed in 1 2 3 4; do
		"$HERE/ghidra-script.sh" raw ARC32:$l:32:default cov_$e.bin CoverageCheck.java "$W/cov_${l}_$seed.txt" 2048 $seed 8 &
	done
	wait
	tot=$(grep -h '^coverage' cov_${l}_1.txt | sed 's/coverage: \([0-9]*\) constructors.*/\1/')
	un=$(cat cov_${l}_*.txt | { grep '^unreached' || true; } | sort | uniq -c | awk '$1==4' | wc -l)
	echo "-- ARC32:$l:32:default: $tot constructors, $((tot - un)) reached by at least one of 4 seeds"
	cat cov_${l}_*.txt | { grep '^unreached' || true; } | sort | uniq -c | awk '$1==4 {print "   " $0}'
	(( un == 0 )) || rc=1
done

echo "== p-code emulator tests"
mkdir -p emu emu_broken
python3 "$HERE/emu_tests.py" emu "$ARC_TOOLS"
python3 "$HERE/emu_tests.py" emu_broken "$ARC_TOOLS" --break 1 >/dev/null
for e in le be; do
	"$HERE/ghidra-script.sh" raw "ARC32:${e^^}:32:default" emu/emu_$e.bin EmuCheck.java \
		"$W/emu/emu_$e.txt" "$W/emu/res_$e.txt" &
done
wait
for e in le be; do
	echo "-- $e: $(tail -n 1 emu/res_$e.txt)"
	if grep -v "^PASS\|^emulator" emu/res_$e.txt; then rc=1; fi
done
"$HERE/ghidra-script.sh" raw ARC32:LE:32:default emu_broken/emu_le.bin EmuCheck.java \
	"$W/emu_broken/emu_le.txt" "$W/emu_broken/res.txt"
if grep -q '^FAIL' emu_broken/res.txt; then
	echo "-- deliberately wrong expectation: $(grep '^FAIL' emu_broken/res.txt)"
else
	echo "FAIL: deliberately wrong expectation NOT DETECTED"; rc=1
fi

if (( REAL )); then
	echo "== real binaries"
	ARC_TOOLS=${ARC_GCC:?set ARC_GCC} "$HERE/build-real-samples.sh" "$W/samples"
	"$HERE/real-binaries.sh" "$W/samples" "$W/real" || rc=1
fi
echo "== done: $([[ $rc == 0 ]] && echo PASS || echo FAIL)"
exit $rc
