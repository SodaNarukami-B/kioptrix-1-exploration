#ifndef SMB
#define SMB

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
  uint8_t type;
  uint8_t flag;
  uint16_t len;
} NBHDR;

typedef struct {
  uint8_t proto[4];
  uint8_t command;
  uint32_t status;
  uint8_t flag;
  uint16_t flag2;
  uint16_t pid_h;
  uint8_t sign[8];
  uint16_t reserved;
  uint16_t tid;
  uint16_t pid;
  uint16_t uid;
  uint16_t mid;
} SMBHDR;

#pragma pack(pop)

void nbios_htonb(uint8_t *in, uint8_t *out);

#endif
