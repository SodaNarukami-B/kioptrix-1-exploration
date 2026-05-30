#ifndef STDSDA
#define STDSDA

#include <stdint.h>
#include <stdio.h>

typedef struct __attribute__((packed)) {
  size_t size;
  uint8_t *buffer;
} soda_sp;

#endif
