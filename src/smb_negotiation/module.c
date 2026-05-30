#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

struct payload_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  uint16_t byte_count;
  uint8_t dialect[12];
};

int smb_negotiation(int sock) {
  // INFO: Payload counstructing
  struct payload_t payload;
  memset(&payload, 0, sizeof(struct payload_t));

  // Net Bios Header
  payload.nb_hdr.length = htons(sizeof(struct payload_t) - 4);

  // Smb Header
  memcpy(payload.smb_hdr.protocol, SMB_PROTO, 4);
  payload.smb_hdr.command = SMB_NEGOTIATION;
  payload.smb_hdr.flag = 0x18;

  // Word count

  // Byte count
  payload.byte_count = htole16(12);

  // Data
  memcpy(payload.dialect, SMB_BASE_DIALECT, 12);

  printf("+ Negotiation: payload created\n");

  if (send(sock, &payload, sizeof(struct payload_t), 0) < 0) {
    printf("- Negotiation: sending failed\n");
    return -1;
  }

  printf("+ Negotiation: payload sended\n");

  uint8_t *recv_buffer = (uint8_t *)calloc(1, 64);
  size_t res = recv(sock, recv_buffer, 64, 0);
  if (res < 0) {
    printf("- Negotiation: receiving failed (timeout error)\n");
    return -1;
  } else if (res == 0) {
    printf("- Negotiation: connection closed by remote host\n");
    return -1;
  }

  struct smb_header *recv_smb_header = (struct smb_header *)(recv_buffer + 4);

  if (recv_smb_header->command == SMB_NEGOTIATION &&
      recv_smb_header->status == 0) {
    printf("+ Negotiation: negotiation complited successfuly\n");
    free(recv_buffer);
    return 0;
  } else {
    printf("- Negotiation: negotiation failed\n");
    return -1;
  }
}
