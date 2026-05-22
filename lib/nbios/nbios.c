#include "./nbios.h"
#include "../stdsda/sda.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sda_sp nbios_htonb(const char *data, size_t data_len) {
  sda_sp result;
  result.size = 32;
  result.buffer = (uint8_t *)calloc(1, result.size);

  if (!result.buffer) {
    result.status = -1;
    return result;
  }

  uint8_t raw_buffer[16];
  memset(&raw_buffer, ' ', 16);

  size_t to_copy = (data_len < 16) ? data_len : 16;
  memcpy(raw_buffer, data, to_copy);

  for (int i = 0; i < data_len; i++) {
    result.buffer[i * 2] = (raw_buffer[i] >> 4) + 0x41;
    result.buffer[i * 2 + 1] = (raw_buffer[i] & 0x0f) + 0x41;
  };

  result.status = 0;

  return result;
  // use free yourself
}
