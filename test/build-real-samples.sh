#!/usr/bin/env bash
# Build the real-code samples for the ARC32 module: freely licensed C compiled with GCC 4.5.4 for
# arc-elf (the last GCC with this target) and GNU binutils 2.25.1, both byte orders. The
# sources are downloaded from pinned URLs and checked against SHA-256; nothing is committed.
#   zlib 1.3.1 (zlib license) with test/real/zmain.c (public domain) -> zlib-{le,be}.elf
#   Brad Conte's crypto-algorithms (public domain): aes, des, blowfish, md5, sha1, sha256
#     with test/real/cmain.c -> crypto-{le,be}.elf
#
#   test/build-real-samples.sh <workdir>
# Environment: ARC_TOOLS   prefix of the toolchain, e.g. .../bin/arc-elf- (gcc, ld, as)
#              LIBGCC_LE, LIBGCC_BE   libgcc.a for each byte order (default: the compiler's)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${ARC_TOOLS:?set ARC_TOOLS to the arc-elf- toolchain prefix}"
W=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$W"

fetch() { # url sha256 file
	[[ -f $3 ]] || curl -sSLf -o "$3" "$1"
	echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch: $3" >&2; exit 1; }
}

fetch https://zlib.net/fossils/zlib-1.3.1.tar.gz \
	9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 zlib-1.3.1.tar.gz
[[ -d zlib-1.3.1 ]] || tar xzf zlib-1.3.1.tar.gz

CA=https://raw.githubusercontent.com/B-Con/crypto-algorithms/cfbde48414baacf51fc7c74f275190881f037d32
mkdir -p crypto
while read -r f sum; do
	fetch "$CA/$f" "$sum" "crypto/$f"
done <"$HERE/real/crypto-files.txt"

mkdir -p inc
printf '#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\nvoid *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t);\nsize_t strlen(const char *);\n' >inc/string.h
cp inc/string.h inc/memory.h
printf '#include <stddef.h>\n' >inc/stdlib.h
cp inc/stdlib.h inc/stdio.h

LIBGCC_LE=${LIBGCC_LE:-$("${ARC_TOOLS}gcc" -print-libgcc-file-name)}
for e in le be; do
	EB=(); [[ $e == be ]] && EB=(-EB)
	lg=LIBGCC_${e^^}; lg=${!lg:-}
	[[ -n $lg ]] || { echo "set LIBGCC_BE (a big-endian libgcc.a) to build the be samples" >&2; continue; }
	mkdir -p "obj-$e"
	for f in adler32 compress crc32 deflate infback inffast inflate inftrees trees uncompr zutil; do
		"${ARC_TOOLS}gcc" "${EB[@]}" -O2 -DZ_SOLO -c "zlib-1.3.1/$f.c" -o "obj-$e/z_$f.o" 2>&1 | grep -v -E "option. directive|Assembler messages" || true
	done
	"${ARC_TOOLS}gcc" "${EB[@]}" -O2 -DZ_SOLO -Izlib-1.3.1 -c "$HERE/real/zmain.c" -o "obj-$e/zmain.o" 2>&1 | grep -v -E "option. directive|Assembler messages" || true
	"${ARC_TOOLS}ld" "${EB[@]}" -Ttext=0x1000 -e __start "obj-$e"/z_*.o "obj-$e/zmain.o" "$lg" -o "zlib-$e.elf"
	for f in aes des blowfish md5 sha1 sha256; do
		"${ARC_TOOLS}gcc" "${EB[@]}" -O2 -Iinc -c "crypto/$f.c" -o "obj-$e/c_$f.o" 2>&1 | grep -v -E "option. directive|Assembler messages" || true
	done
	"${ARC_TOOLS}gcc" "${EB[@]}" -O2 -Iinc -Icrypto -c "$HERE/real/cmain.c" -o "obj-$e/cmain.o" 2>&1 | grep -v -E "option. directive|Assembler messages" || true
	"${ARC_TOOLS}ld" "${EB[@]}" -Ttext=0x1000 -e __start "obj-$e"/c_*.o "obj-$e/cmain.o" "$lg" -o "crypto-$e.elf"
done
ls -l ./*.elf
