#ifndef NBIOS
#define NBIOS

#define NBIOS_SESSION_REQUEST 0x81
#define NBIOS_SESSION_GRANTED 0x82
#define NBIOS_SESSION_DENIED 0x83

#define NBIOS_WILDCARD "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#include "../stdsda/stdsda.h"
#include <stdint.h>
#include <stdio.h>

struct nbios_header {
  uint8_t type;
  uint8_t flag;
  uint16_t length; // Be carefull: length always in BE. Use htons()
} __attribute__((packed));

uint8_t *nbios_htonb(const char *data, size_t size);

int nbios_session_setup(int sock);

#endif
