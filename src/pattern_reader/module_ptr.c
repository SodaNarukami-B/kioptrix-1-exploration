#ifndef PATTERN_READER
#define PATTERN_READER

#include <stdint.h>
#include <stdio.h>

int read_pattern(const char *path, uint8_t *dest, size_t dest_s);

#endif
