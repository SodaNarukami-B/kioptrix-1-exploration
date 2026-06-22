#ifndef NBIOS
#define NBIOS

#define NBIOS_COM_SESSION_SETUP 0x81

#include <stdint.h>
#include <stdio.h>

struct nbios_header {
  uint8_t nb_type;
  uint8_t nb_flag;
  uint16_t nb_length;
} __attribute__((packed));

#endif
