#!/usr/bin/env bash
# Import real legacy-ARC (ARC32) ELF files headless (no -processor: the ELF opinion picks the language),
# run auto-analysis, decompile every function, and compare every instruction Ghidra found with
# GNU libopcodes at the same address (realcmp.py).
#
#   test/real-binaries.sh <samples-dir> [workdir]      (samples: test/build-real-samples.sh)
#
# Environment: GHIDRA_INSTALL_DIR, SLOTDIS25 (slotdis25 binary), DECOMP_TIMEOUT (seconds per
#   function, default 60), JOBS (parallel imports, default 4)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
: "${SLOTDIS25:?set SLOTDIS25}"
TMO=${DECOMP_TIMEOUT:-60}
SAMPLES=$(readlink -f "$1")
W=$(readlink -f "${2:-real-work}")
mkdir -p "$W"

mapfile -t files < <(find "$SAMPLES" -type f -name '*.elf' | sort)
run_one() { # file
	local f=$1 n p imp=()
	n=$(basename "$f")
	# shared objects are imported at their link address (0) so that addresses match objdump
	[[ $(python3 -I -c 'import sys; h=open(sys.argv[1],"rb").read(18); print(int.from_bytes(h[16:18], "little" if h[5]==1 else "big"))' "$f") == 3 ]] &&
		imp=(-loader ElfLoader -loader-imagebase 0)
	p=$(mktemp -d "${TMPDIR:-/tmp}/arc32-real.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$f" "${imp[@]}" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" "$TMO" \
		-deleteProject >"$W/$n.log" 2>&1 || { tail -20 "$W/$n.log" >&2; }
	rm -rf "$p"
}
echo "== headless import + analysis + decompile (${#files[@]} files)"
for f in "${files[@]}"; do
	while (( $(jobs -rp | wc -l) >= ${JOBS:-4} )); do wait -n; done
	run_one "$f" &
done
wait

rc=0
echo "== results"
for f in "${files[@]}"; do
	n=$(basename "$f")
	echo "-- $n"
	grep -E "^(language|functions|instructions|fallthrough|bad-instruction|error bookmarks|relocations|decompile|functions whose)" "$W/$n.sum" | sed 's/^/   /'
	python3 "$HERE/realcmp.py" "$f" "$W/$n.lst" "$SLOTDIS25" "$W/$n" >"$W/$n.cmp" || rc=1
	echo "   vs objdump: $(head -1 "$W/$n.cmp")"
done
echo "(full outputs: $W/<file>.{sum,lst,c,cmp,log})"
exit $rc
