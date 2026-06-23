#ifndef SMB_COM_NT_CREATE_ANDX
#define SMB_COM_NT_CREATE_ANDX

#include <stdint.h>

int smb_com_nt_create_andx(int sock, uint16_t uid, uint16_t tid);

#endif
