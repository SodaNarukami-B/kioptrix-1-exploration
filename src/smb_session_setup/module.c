#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"
#include "../../lib/stdsda/sda.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#pragma pack(push, p1, 1)

struct data_payload {
  uint8_t oem_password;
  uint8_t uni_password;
  uint8_t account_name;
  uint8_t primary_domain[8];
  uint8_t native_os[5];
  uint8_t native_lan_man[6];
};

struct packet_t {
  struct nbios_header nbhdr;
  struct smb_header smbhdr;
  uint8_t word_count;
  struct smb_session_setup_andx smbssa;
  uint16_t byte_count;
  struct data_payload data;
};

#pragma pack(pop, p1)

sda_sp *smb_send_session_setup(int sock) {
  sda_sp *result = (sda_sp *)calloc(1, sizeof(sda_sp));
  if (result == NULL) {
    return NULL;
  }

  return 0; // INDEV
}
