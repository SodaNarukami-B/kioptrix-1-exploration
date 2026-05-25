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

struct smb_session_setup_andx {
  uint8_t andx_command;
  uint8_t andx_zero;
  uint16_t andx_offset;
  uint16_t max_buffer;
  uint16_t max_mpx;
  uint16_t virtual_channel;
  uint32_t session_key;
  uint16_t oem_pass_len;
  uint16_t uni_pass_len;
  uint32_t zero;
  uint32_t capabilities;
};

#pragma pack(pop, p1)

sda_sp *smb_send_negotiation(int sock);
sda_sp *smb_send_session_setup(int sock);

#endif
