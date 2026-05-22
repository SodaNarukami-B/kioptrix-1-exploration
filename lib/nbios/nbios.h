#ifndef NBIOS
// INFO: Macro
#define NBIOS

#define NBIOS_SESSION_REQ 0x81
#define NBIOS_SESSION_GRN 0x82
#define NBIOS_SESSION_DEN 0x83

#define NBIOS_WILD_CARD "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// INFO: Includes
#include "../stdsda/sda.h"
#include <stdint.h>
#include <stdio.h>

// INFO: Structures
#pragma pack(push, p1, 1)

struct nbios_header {
  uint8_t type;
  uint8_t flag;
  uint16_t length;
};

#pragma pack(pop, p1)

// INFO: Functions
sda_sp nbios_htonb(const char *data, size_t data_len);

sda_sp *nbios_send_session_req(int sock);

#endif
