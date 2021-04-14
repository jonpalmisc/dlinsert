#include "fileutils.h"

#include <sys/param.h>
#include <sys/stat.h>

#define BUFFER_SIZE 512

void fbzero(FILE *f, off_t start, size_t len) {
  static unsigned char zb[BUFFER_SIZE] = {0};

  fseeko(f, start, SEEK_SET);

  while (len != 0) {
    size_t size = MIN(len, sizeof(zb));
    fwrite(zb, size, 1, f);

    len -= size;
  }
}

void fmemmove(FILE *f, off_t dest, off_t src, size_t len) {
  static unsigned char tb[BUFFER_SIZE];

  while (len != 0) {
    size_t size = MIN(len, sizeof(tb));

    // Read the source buffer.
    fseeko(f, src, SEEK_SET);
    fread(&tb, size, 1, f);

    // Write the transfer buffer to the destination.
    fseeko(f, dest, SEEK_SET);
    fwrite(tb, size, 1, f);

    len -= size;
    src += size;
    dest += size;
  }
}

size_t fpeek(void *restrict ptr, size_t size, size_t count,
             FILE *restrict stream) {
  off_t pos = ftello(stream);
  size_t result = fread(ptr, size, count, stream);
  fseeko(stream, pos, SEEK_SET);

  return result;
}

int file_exists(const char *p) {
  struct stat s;
  return stat(p, &s) == 0;
}
