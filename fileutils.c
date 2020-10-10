#include "fileutils.h"

#include <sys/param.h>

#define BUFSIZE 512

void fbzero(FILE* f, off_t offset, size_t len)
{
    static unsigned char zeros[BUFSIZE] = { 0 };
    fseeko(f, offset, SEEK_SET);
    while (len != 0) {
        size_t size = MIN(len, sizeof(zeros));
        fwrite(zeros, size, 1, f);
        len -= size;
    }
}

void fmemmove(FILE* f, off_t dst, off_t src, size_t len)
{
    static unsigned char buf[BUFSIZE];
    while (len != 0) {
        size_t size = MIN(len, sizeof(buf));
        fseeko(f, src, SEEK_SET);
        fread(&buf, size, 1, f);
        fseeko(f, dst, SEEK_SET);
        fwrite(buf, size, 1, f);

        len -= size;
        src += size;
        dst += size;
    }
}

size_t fpeek(void* restrict ptr, size_t size, size_t nitems, FILE* restrict stream)
{
    off_t pos = ftello(stream);
    size_t result = fread(ptr, size, nitems, stream);
    fseeko(stream, pos, SEEK_SET);
    return result;
}