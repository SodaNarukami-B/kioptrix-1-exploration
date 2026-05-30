#include "./nbios.h"
#include <stdlib.h>
#include <string.h>

// nbios_htonb accepts pointer to data and size of data
// returns 32 bytes
uint8_t *nbios_htonb(const char *data, size_t size) {
  uint8_t *buffer = (uint8_t *)calloc(1, 32);

  uint8_t raw[16] = {0};
  if (size >= 16) {
    memcpy(raw, (uint8_t *)data, 16);
  } else {
    memset(raw, ' ', 16);
    memcpy(raw, data, size);
  }

  for (int i = 0; i < 16; i++) {
    buffer[i * 2] = (raw[i] >> 4) + 0x41;
    buffer[i * 2 + 1] = (raw[i] & 0x0f) + 0x41;
  }

  return buffer;
}
