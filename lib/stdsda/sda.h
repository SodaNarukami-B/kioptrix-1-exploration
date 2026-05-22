#ifndef STDSDA
#define STDSDA

#include <stdint.h>
#include <stdio.h>

#pragma pack(push, p1, 1)

typedef struct {
  uint8_t status;
  size_t size;
  uint8_t *buffer;
} sda_sp;

#pragma pack(pop, p1)

#endif
