#ifndef SMB_COM_TRANS2_OPEN2
#define SMB_COM_TRANS2_OPEN2

#include <stdint.h>

int smb_com_trans2_open2(int sock, uint16_t tid, uint16_t uid);

#endif
