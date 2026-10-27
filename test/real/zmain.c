/* Freestanding driver for the zlib test image: a tiny C runtime (memory functions and a bump
 * allocator) and a round trip through compress2/uncompress. Written for Ghidra-Rare's ARC32
 * real-code test; public domain. */
#include "zlib.h"

typedef unsigned long size_t_;
void *memcpy(void *d, const void *s, size_t_ n) { char *dd = d; const char *ss = s; while (n--) *dd++ = *ss++; return d; }
void *memset(void *d, int c, size_t_ n) { char *dd = d; while (n--) *dd++ = (char)c; return d; }
int memcmp(const void *a, const void *b, size_t_ n) {
	const unsigned char *x = a, *y = b;
	for (; n; n--, x++, y++) if (*x != *y) return *x - *y;
	return 0;
}
size_t_ strlen(const char *s) { size_t_ n = 0; while (s[n]) n++; return n; }

static unsigned char heap[256 * 1024];
static size_t_ heap_top;
static voidpf zalloc(voidpf opaque, uInt items, uInt size) {
	size_t_ n = ((size_t_)items * size + 7) & ~7ul;
	void *p;
	(void)opaque;
	if (heap_top + n > sizeof heap) return Z_NULL;
	p = heap + heap_top;
	heap_top += n;
	return p;
}
static void zfree(voidpf opaque, voidpf p) { (void)opaque; (void)p; }

static unsigned char src[4096], packed[8192], unpacked[4096];
volatile int result;

static int roundtrip(int level) {
	z_stream s;
	int i, err;
	for (i = 0; i < (int)sizeof src; i++) src[i] = (unsigned char)(i * 7 + (i >> 5));
	memset(&s, 0, sizeof s);
	s.zalloc = zalloc; s.zfree = zfree;
	if (deflateInit(&s, level) != Z_OK) return -1;
	s.next_in = src; s.avail_in = sizeof src;
	s.next_out = packed; s.avail_out = sizeof packed;
	err = deflate(&s, Z_FINISH);
	deflateEnd(&s);
	if (err != Z_STREAM_END) return -2;
	memset(&s, 0, sizeof s);
	s.zalloc = zalloc; s.zfree = zfree;
	if (inflateInit(&s) != Z_OK) return -3;
	s.next_in = packed; s.avail_in = sizeof packed - s.avail_out;
	s.next_out = unpacked; s.avail_out = sizeof unpacked;
	err = inflate(&s, Z_FINISH);
	inflateEnd(&s);
	if (err != Z_STREAM_END) return -4;
	return memcmp(src, unpacked, sizeof src) == 0 ? (int)adler32(1, unpacked, sizeof unpacked) : -5;
}

void _start(void) {
	result = roundtrip(6) ^ (int)crc32(0, src, 16);
	for (;;)
		;
}
