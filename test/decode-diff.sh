#!/usr/bin/env bash
# Decode the corpora (gen_corpus.py) with Ghidra and with libopcodes 2.25.1 and compare, both
# byte orders.   test/decode-diff.sh <workdir>
# Environment: GHIDRA_INSTALL_DIR, SLOTDIS25 (slotdis25 binary built from test/slotdis25.c)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
W=$(readlink -f "$1")
cd "$W"
rc=0
for e in le be; do
	L=ARC32:${e^^}:32:default
	eb=little; [[ $e == be ]] && eb=big
	pids=()
	for c in fields low fuzz; do
		rm -f g_${c}_$e.txt
		"$HERE/ghidra-slots.sh" "$L" ${c}_$e.bin 8 g_${c}_$e.txt 2>/dev/null &
		pids+=($!)
	done
	for p in "${pids[@]}"; do wait "$p"; done
	for c in fields low fuzz; do
		"$SLOTDIS25" 8 ${c}_$e.bin -e $eb >o_${c}_$e.txt
		python3 "$HERE/compare.py" g_${c}_$e.txt o_${c}_$e.txt >cmp_${c}_$e.txt || rc=1
		echo "-- $c $e: $(head -1 cmp_${c}_$e.txt)"
	done
done
exit $rc
