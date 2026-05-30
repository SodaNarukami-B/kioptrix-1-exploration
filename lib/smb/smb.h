#ifndef SMB
#define SMB

#define SMB_PROTO "\xffSMB"
#define SMB_NEGOTIATION 0x72
#define SMB_SESSION_SETUP 0x73

#define SMB_BASE_DIALECT "\x02NT LM 0.12\x00"

#include <stdint.h>

#pragma pack(push, p1, 1)

struct smb_header {
  uint8_t protocol[4];
  uint8_t command;
  uint32_t status;
  uint8_t flag;
  uint16_t flag2;
  uint16_t PID_high;
  uint8_t signature[8];
  uint16_t reserved; // zero
  uint16_t tid;
  uint16_t pid;
  uint16_t uid;
  uint16_t mid;
};

#pragma pack(pop, p1)

int smb_negotiation(int sock);

#endif
