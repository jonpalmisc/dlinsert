#ifndef DL_INSERT_FILEUTILS_H
#define DL_INSERT_FILEUTILS_H

#include <stdio.h>

void fbzero(FILE* f, off_t offset, size_t len);
void fmemmove(FILE* f, off_t dst, off_t src, size_t len);
size_t fpeek(void* restrict ptr, size_t size, size_t nitems, FILE* restrict stream);

#endif