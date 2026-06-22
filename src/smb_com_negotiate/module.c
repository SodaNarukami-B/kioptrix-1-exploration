// Network
#include <arpa/inet.h>
#include <sys/socket.h>

// std
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// custom
#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"
#include "./module_ptr.h"

// structs
struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  uint16_t byte_count;
  uint8_t dialect[12];
} __attribute__((packed));

int smb_com_negotiate(int sock) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // netbios
  packet.nb_hdr.nb_length = htons(sizeof(struct packet_t) - 4);

  // smb header
  memcpy(packet.smb_hdr.protocol, SMB_PROTOCOL, 4);
  packet.smb_hdr.command = SMB_COM_NEGOTIATION;
  packet.smb_hdr.flag = 0x08;    // caseless pathnames
  packet.smb_hdr.flag2 = 0x0001; // long files support

  // byte count
  packet.byte_count = 12;

  // data bytes
  memcpy(packet.dialect, "\x02NT LM 0.12\x00", 12);

  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    return -1;
  };

  uint8_t *res = (uint8_t *)calloc(1, 128);

  if (recv(sock, res, 128, 0) <= 0) {
    free(res);
    return -1;
  }

  /* Debug
  printf("\n");
  for (int i = 0; i < 128; i++) {
    printf("%02x%s", res[i], ((i + 1) % 16 == 0) ? "\n" : " ");
  }
  printf("\n");
  */

  struct smb_header *res_smb_hdr = (struct smb_header *)(res + 4);

  uint8_t res_command = res_smb_hdr->command;
  uint32_t res_status = res_smb_hdr->status;

  free(res);

  if (res_command == SMB_COM_NEGOTIATION && res_status == 0) {
    return 0;
  } else {
    return -1;
  }
}
