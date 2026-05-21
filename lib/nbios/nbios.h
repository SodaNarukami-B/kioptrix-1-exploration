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
struct sda_sp nbios_htonb(const char *data, size_t data_len);

struct sda_sp *nbios_send_session_req(int sock);
// Names contatins 2 parameters (in buffer) - [size][server name] and
// [size][source name].
// Example: [0x0400 S A M B A 0x0400 S O D A ] (hex)
// Hint: if buffer[0] byte is '*' (0x2A00 in hex), function
// sends wild card as server name

#endif
