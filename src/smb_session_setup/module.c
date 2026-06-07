#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#pragma pack(push, p1, 1)

struct data_t {
  uint8_t oem_password;
  uint8_t uni_password;
  uint8_t account_name;
  uint8_t primary_domain[8];
  uint8_t native_os[5];
  uint8_t native_lan_man[6];
};

struct payload_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct smb_session_setup_and_x smb_ssax;
  uint16_t byte_count;
  struct data_t data;
};

#pragma pack(pop, p1)

uint16_t smb_session_setup(int sock) {
  // INFO: Payload counstructing

  struct payload_t payload;
  memset(&payload, 0, sizeof(struct payload_t));

  // Net Bios
  payload.nb_hdr.length = htons(sizeof(struct payload_t) - 4);

  // Smb Header
  memcpy(payload.smb_hdr.protocol, SMB_PROTO, 4);
  payload.smb_hdr.command = SMB_SESSION_SETUP;
  payload.smb_hdr.flag = 0x18;

  // Word count
  payload.word_count = 13;

  // Smb Session Setup And X

  payload.smb_ssax.andx_command = 0xff;
  payload.smb_ssax.max_buffer = 0xffff;
  payload.smb_ssax.max_mpx = 1;
  payload.smb_ssax.oem_password_len = 1;
  payload.smb_ssax.uni_password_len = 1;

  // Byte count
  payload.byte_count = htole16(sizeof(struct data_t));

  // Data
  memcpy(payload.data.primary_domain, "MYGROUP\x00", 8);
  memcpy(payload.data.native_os, "UNIX\x00", 5);
  memcpy(payload.data.native_lan_man, "SAMBA\x00", 6);

  printf("+ Smb session: payload created\n");

  // INFO: Sending
  if (send(sock, &payload, sizeof(struct payload_t), 0) < 0) {
    printf("- Smb session: sending failed (timeout error)\n");
    return -1;
  }

  printf("+ Smb session: payload sended\n");

  // INFO: Receiving
  uint8_t *recv_buffer = (uint8_t *)calloc(1, 128);
  int res = recv(sock, recv_buffer, 128, 0);

  if (res < 0) {
    printf("- Smb session: failed to receive (timeout error)\n");

    free(recv_buffer);
    return -1;
  } else if (res == 0) {
    printf("- Smb session: connection closed by remote host\n");

    free(recv_buffer);
    return -1;
  } else {
    struct smb_header *recv_smb_header = (struct smb_header *)(recv_buffer + 4);

    if (recv_smb_header->command == SMB_SESSION_SETUP &&
        recv_smb_header->status == 0) {

      printf("+ Smb session: session granted\n");

      free(recv_buffer);
      return recv_smb_header->uid;
    } else {
      printf("- Smb session: session denied (err code: %08x - reversed)\n",
             recv_smb_header->status);

      free(recv_buffer);
      return -1;
    }
  }
}
