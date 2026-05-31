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

struct smb_session_setup_and_x {
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint16_t max_buffer;
  uint16_t max_mpx;
  uint16_t virtual_channel;
  uint32_t session_key;
  uint16_t oem_password_len;
  uint16_t uni_password_len;
  uint32_t reserved;
  uint32_t capabilities;
};

#pragma pack(pop, p1)

int smb_negotiation(int sock);
uint16_t smb_session_setup(int sock);

#endif
