#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"
#include "../../lib/stdsda/sda.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

struct payload_t {
  struct nbios_header nbhdr;
  struct smb_header smbhdr;
  uint8_t word_count;  // always zero
  uint16_t byte_count; // 12
  uint8_t dialect[12];
} __attribute__((packed));

sda_sp *smb_send_negotiation(int sock) {

  sda_sp *result = (sda_sp *)calloc(1, sizeof(sda_sp));

  // INFO: payload configurating
  struct payload_t payload;

  struct nbios_header *nbhdr = &payload.nbhdr;

  nbhdr->type = 0;
  nbhdr->flag = 0;
  nbhdr->length = htons(sizeof(struct payload_t) - 4);

  // Smb header
  struct smb_header *smbhdr = &payload.smbhdr;

  memcpy(smbhdr->protocol, SMB_MAGIC, 4);
  smbhdr->command = SMB_NEGOTIATION;
  smbhdr->status = 0;
  smbhdr->flag = 0x18;
  smbhdr->flag2 = 0;
  smbhdr->PID_high = 0;
  memset(smbhdr->signature, 0, 8);
  smbhdr->zero = 0;
  smbhdr->tid = 0;
  smbhdr->pid = 0;
  smbhdr->uid = 0;
  smbhdr->mid = 0;

  // Word count & Byte count
  payload.word_count = 0;
  payload.byte_count = htole16(12);

  // Dialect
  memcpy(payload.dialect, "\x02NT LM 0.12\x00", 12);

  printf("+ Smb neg > info: payload created\n");

  // INFO: Sending
  if (send(sock, &payload, sizeof(struct payload_t), 0) < 0) {
    printf("- Smb neg > err: failed to send payload (connection timeout)\n");
    result->status = -1;
    return result;
  }
  printf("+ Smb neg > info: payload sended\n");

  // INFO: Receiving
  uint8_t *recv_buffer = (uint8_t *)calloc(1, 64);

  if (recv(sock, recv_buffer, 64, 0) < 0) {
    free(recv_buffer);
    printf("- Smb neg > err: failed to receive (connection timeout)\n");
    result->status = -1;
    return result;
  }

  if (recv_buffer[8] != SMB_NEGOTIATION || *(uint32_t *)&recv_buffer[9] != 0) {

    printf("- Smb neg > err: negotiation failed (status: %04x)\n",
           *(uint32_t *)&recv_buffer[10]);

    free(recv_buffer);

    result->status = -1;
    return result;
  } else {
    free(recv_buffer);

    printf("+ Smb neg > info: negotiation complited successfuly\n");

    result->status = 0;
    return result;
  }
}
