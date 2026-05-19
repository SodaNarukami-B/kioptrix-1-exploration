#ifndef STDSDA
#define STDSDA

#include <stdint.h>
#include <stdio.h>

#pragma pack(push, p1, 1)

// Smart pointer
typedef struct {
  size_t size;
  uint8_t *buffer;
} sda_sp;

#pragma pack(pop, p1)

typedef sda_sp *(*callback)(int, sda_sp *);

sda_sp *call_func(callback func, int arg, sda_sp *data, const char *log,
                  size_t log_len);

#endif
