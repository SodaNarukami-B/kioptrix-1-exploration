#ifndef SMB
#define SMB

#define SMB_PROTO "\xffSMB"
#define SMB_NEGOTIATION 0x72
#define SMB_SESSION_SETUP 0x73
#define SMB_TREE_CONNECT 0x75
#define SMB_NT_CREATE 0xA2
#define SMB_TRANS2 0x32

#define SMB_BASE_DIALECT "\x02NT LM 0.12"
#define SMB_SERVICE "IPC"
#define SMB_TREE_PATH "\\\\192.168.1.104\\IPC$"

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

struct smb_tree_connect_and_x {
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint16_t disconnect_flags;
  uint16_t password_len;
};

struct smb_nt_create_andx {
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint8_t reserved;
  uint16_t name_length;
  uint32_t flags;
  uint32_t fid;
  uint32_t desired_access;
  uint64_t allocation_size;
  uint32_t file_attributes;
  uint32_t share_access;
  uint32_t create_disposition;
  uint32_t create_options;
  uint32_t impersonation_level;
  uint8_t security_flags;
};

struct smb_trans2 {
  uint16_t total_parameter_count;
  uint16_t total_data_count;
  uint16_t max_parameter_count;
  uint16_t max_data_count;
  uint8_t max_setup_count;
  uint8_t reserved1;
  uint16_t flags;
  uint32_t timeout;
  uint16_t reserved2;
  uint16_t parameter_count;
  uint16_t parameter_offset;
  uint16_t data_count;
  uint16_t data_offset;
  uint8_t setup_count;
  uint8_t reserved3;
  uint16_t setup_words;
};

#pragma pack(pop, p1)

int smb_negotiation(int sock);
uint16_t smb_session_setup(int sock);
uint16_t smb_tree_connect(int sock, uint16_t uid);
uint16_t smb_nt_create(int sock, uint16_t uid, uint16_t tid);
int smb_trans2open(int sock, uint16_t uid, uint16_t tid);

#endif
