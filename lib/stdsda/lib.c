#include "./lib.h"
#include <stdint.h>

sda_sp *call_func(callback func, int arg, sda_sp *data, const char *log,
                  size_t log_len) {
  sda_sp *sp = func(arg, data);
  uint8_t status = (sp && sp->buffer) ? sp->buffer[0] : 0xFF;

  printf("[TRACE] %p returned %02x (info: %.*s)\n", (void *)func, status,
         (int)log_len, log);

  return sp;
};
