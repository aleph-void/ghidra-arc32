/* Disassemble the first instruction of every fixed-size slot of a raw file with the legacy ARC
 * (ARCtangent-A4/A5) disassembler of GNU libopcodes 2.25.1 (the last release with that target).
 *   slotdis25 <slot> <file> [-e big] [-m <mach>] [-l <address-list> -b <base-vma>]
 * Prints "<offset-hex> <len> <text>" per slot ("<offset> 0 (bad)" when libopcodes fails).
 * With -l, <file> is a raw image loaded at <base-vma> and one instruction is disassembled at each
 * address listed (hex, first field of each line). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "bfd.h"
#include "dis-asm.h"

static char buf[512]; static size_t blen;
static int pf(void *s, const char *fmt, ...) { va_list ap; va_start(ap, fmt);
  int n = vsnprintf(buf + blen, sizeof buf - blen, fmt, ap); va_end(ap); if (n > 0) blen += n; return n; }
static void paddr(bfd_vma a, struct disassemble_info *i) { pf(0, "0x%lx", (unsigned long)a); }

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage\n"); return 2; }
  const char *lst = NULL, *mach = "arc"; int big = 0; unsigned long base = 0;
  for (int i = 3; i + 1 < argc; i += 2) {
    if (!strcmp(argv[i], "-e")) big = !strcmp(argv[i + 1], "big");
    else if (!strcmp(argv[i], "-m")) mach = argv[i + 1];
    else if (!strcmp(argv[i], "-l")) lst = argv[i + 1];
    else if (!strcmp(argv[i], "-b")) base = strtoul(argv[i + 1], NULL, 16);
  }
  bfd_init();
  bfd *abfd = bfd_openw("/dev/null", big ? "elf32-bigarc" : "elf32-littlearc");
  if (!abfd || !bfd_set_format(abfd, bfd_object)) { fprintf(stderr, "bfd\n"); return 2; }
  const bfd_arch_info_type *ai = bfd_scan_arch(mach);
  if (!ai) { fprintf(stderr, "unknown arch %s\n", mach); return 2; }
  bfd_set_arch_mach(abfd, ai->arch, ai->mach);
  int slot = atoi(argv[1]);
  FILE *f = fopen(argv[2], "rb"); fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
  unsigned char *data = malloc(sz); if (fread(data, 1, sz, f) != (size_t)sz) return 2; fclose(f);
  disassembler_ftype d = disassembler(abfd);
  FILE *lf = lst ? fopen(lst, "r") : NULL;
  char line[1024];
  for (long off = 0;; off += slot) {
    unsigned long vma = off;
    long avail = slot;
    if (lf) {
      if (!fgets(line, sizeof line, lf)) break;
      vma = strtoul(line, NULL, 16);
      off = (long)(vma - base);
      if (off < 0 || off >= sz) continue;
      avail = sz - off;
    } else if (off + slot > sz) break;
    struct disassemble_info info;
    init_disassemble_info(&info, NULL, (fprintf_ftype) pf);
    info.arch = ai->arch; info.mach = ai->mach;
    info.endian = big ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
    if (lf) { info.buffer = data; info.buffer_vma = base; info.buffer_length = sz; }
    else { info.buffer = data + off; info.buffer_vma = off; info.buffer_length = avail; }
    info.print_address_func = paddr;
    disassemble_init_for_target(&info);
    blen = 0; buf[0] = 0;
    int n = d(lf ? vma : (unsigned long)off, &info);
    for (char *p = buf; *p; p++) if (*p == '\t' || *p == '\n') *p = ' ';
    if (n <= 0) printf("%08lx 0 (bad)\n", lf ? vma : (unsigned long)off);
    else printf("%08lx %d %s\n", lf ? vma : (unsigned long)off, n, buf);
  }
  return 0;
}
