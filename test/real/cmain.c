/* Freestanding driver for the crypto-algorithms test image: memory functions and one call into
 * each algorithm. Written for Ghidra-Rare's ARC32 real-code test; public domain. */
#include <string.h>

/* The headers each define BYTE and WORD, which C89 does not allow twice in one unit: the
 * entry points are declared here instead (same ABI; contexts as opaque, large enough buffers). */
typedef unsigned char BYTE;
typedef unsigned int WORD;
typedef struct { WORD w[1024 + 18]; } BLOWFISH_KEY;
typedef struct { WORD w[64]; } MD5_CTX, SHA1_CTX, SHA256_CTX;
enum { DES_ENCRYPT, DES_DECRYPT };
void aes_key_setup(const BYTE key[], WORD w[], int keysize);
int aes_encrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[]);
void des_key_setup(const BYTE key[], BYTE schedule[][6], int mode);
void des_crypt(const BYTE in[], BYTE out[], const BYTE key[][6]);
void blowfish_key_setup(const BYTE user_key[], BLOWFISH_KEY *keystruct, size_t len);
void blowfish_encrypt(const BYTE in[], BYTE out[], const BLOWFISH_KEY *keystruct);
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const BYTE data[], size_t len);
void md5_final(MD5_CTX *ctx, BYTE hash[]);
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

void *memcpy(void *d, const void *s, size_t n) { char *dd = d; const char *ss = s; while (n--) *dd++ = *ss++; return d; }
void *memset(void *d, int c, size_t n) { char *dd = d; while (n--) *dd++ = (char)c; return d; }
int memcmp(const void *a, const void *b, size_t n) {
	const unsigned char *x = a, *y = b;
	for (; n; n--, x++, y++) if (*x != *y) return *x - *y;
	return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static BYTE heap[8192];
static size_t heap_top;
void *malloc(size_t n) {
	void *p;
	n = (n + 7) & ~(size_t)7;
	if (heap_top + n > sizeof heap) return 0;
	p = heap + heap_top;
	heap_top += n;
	return p;
}
void free(void *p) { (void)p; }

static BYTE text[64] = "The quick brown fox jumps over the lazy dog, twice over";
static BYTE key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
volatile unsigned result;

void _start(void) {
	BYTE out[64], hash[32], iv[16] = { 0 };
	WORD ks[60];
	BYTE dk[16][6];
	BLOWFISH_KEY bk;
	MD5_CTX m; SHA1_CTX s1; SHA256_CTX s2;
	unsigned acc = 0;
	int i;

	aes_key_setup(key, ks, 256);
	aes_encrypt_cbc(text, 64, out, ks, 256, iv);
	acc ^= out[63];
	des_key_setup(key, dk, DES_ENCRYPT);
	des_crypt(text, out, (const BYTE (*)[6])dk);
	acc ^= out[7];
	blowfish_key_setup(key, &bk, 16);
	blowfish_encrypt(text, out, &bk);
	acc ^= out[0];
	md5_init(&m); md5_update(&m, text, strlen((char *)text)); md5_final(&m, hash);
	acc ^= hash[15];
	sha1_init(&s1); sha1_update(&s1, text, 64); sha1_final(&s1, hash);
	acc ^= hash[19];
	sha256_init(&s2); sha256_update(&s2, text, 64); sha256_final(&s2, hash);
	for (i = 0; i < 32; i++)
		acc = acc * 31 + hash[i];
	result = acc;
	for (;;)
		;
}
