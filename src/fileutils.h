#ifndef DL_INSERT_FILEUTILS_H
#define DL_INSERT_FILEUTILS_H

#include <stdio.h>

void fbzero(FILE *, off_t start, size_t len);
void fmemmove(FILE *, off_t dest, off_t src, size_t len);
size_t fpeek(void *restrict ptr, size_t size, size_t count, FILE *restrict);

int file_exists(const char *p);

#endif
