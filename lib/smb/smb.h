#ifndef SMB
#define SMB

#define SMB_PROTOCOL "\xffSMB"

#define SMB_COM_NEGOTIATION 0x72
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/96ccc2bd-67ba-463a-bb73-fd6a9265199e/

#define SMB_COM_SESSION_SETUP_ANDX 0x73
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/d902407c-e73b-46f5-8f9e-a2de2b6085a2/

#define SMB_COM_TREE_CONNECT_ANDX 0x75
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/a105173a-d854-4950-be28-3d3240529ec3

#define SMB_COM_NT_CREATE_ANDX 0xa2
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/d3f83a7e-493b-4d29-b21c-55768b93e144

#define SMB_COM_TRANSACTION2 0x32
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/714bb6fa-7fab-4dab-8ff8-8a01c273b9ce
// WARN: Here's 2 versions of documentation. Try both in code!

#include <stdint.h>

struct smb_header {
  uint8_t protocol[4];
  uint8_t command;
  uint32_t status;
  uint8_t flag;
  uint16_t flag2;
  uint16_t PID_high;
  uint8_t signature[8];
  uint16_t reserved;
  uint16_t tid;
  uint16_t pid;
  uint16_t uid;
  uint16_t mid;
} __attribute__((packed));

#endif
