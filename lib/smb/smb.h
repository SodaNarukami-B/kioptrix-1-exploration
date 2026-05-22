#ifndef SMB
#define SMB

// INFO: Macroses
#define SMB_MAGIC "\xffSMB"
#define SMB_NEGOTIATION 0x72

// INFO: Includes
#include "../stdsda/sda.h"
#include <stdint.h>
#include <stdio.h>

#pragma pack(push, p1, 1)

struct smb_header {
  uint8_t protocol[4];
  uint8_t command;
  uint32_t status;
  uint8_t flag;
  uint16_t flag2;
  uint16_t PID_high;
  uint8_t signature[8];
  uint16_t zero;
  uint16_t tid;
  uint16_t pid;
  uint16_t uid;
  uint16_t mid;
};

#pragma pack(pop, p1)

sda_sp *smb_send_negotiation(int sock);

#endif
