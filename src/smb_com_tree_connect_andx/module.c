
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

// static

static uint8_t TREE_PATH[21] = "\\\\192.168.1.104\\IPC$\x00";
static uint8_t TREE_SERVICE[5] = "IPC$\x00";

// structs
#pragma pack(push, p1, 1)

struct params_t {
  uint8_t andx_command;
  uint8_t reserved;
  uint16_t andx_offset;
  uint16_t flag;
  uint16_t pass_len;
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct params_t params;
  uint16_t byte_count;
  uint8_t data_bytes[28];
};

#pragma pack(pop, p1)

short smb_com_tree_connect_andx(int sock, uint16_t uid) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // Nbios hdr
  packet.nb_hdr.nb_length = htons(sizeof(struct packet_t) - 4);

  // smb hdr
  memcpy(packet.smb_hdr.protocol, SMB_PROTOCOL, 4);
  packet.smb_hdr.command = SMB_COM_TREE_CONNECT_ANDX;
  packet.smb_hdr.flag = 0x08;
  packet.smb_hdr.flag2 = 0x0001;
  packet.smb_hdr.uid = uid;

  // word count
  packet.word_count = 0x04;

  // params
  packet.params.andx_command = 0xff;
  packet.params.pass_len = 1;

  packet.byte_count = 0x001d;

  memcpy(packet.data_bytes + 1, TREE_PATH, 21);
  // 1 byte pad
  memcpy(packet.data_bytes + 23, TREE_SERVICE, 5);

  /* DEBUG
  printf("\nDEBUG:\n");
  for (int i = 0; i < sizeof(packet.data_bytes); i++) {
    printf("%02x%s", packet.data_bytes[i],
           (((i + 1) % 16 == 0) || i == sizeof(packet.data_bytes) - 1) ? "\n"
                                                                       : " ");
  };
  printf("EOF\n");
  */

  // sending
  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    return 0;
  };

  // receiving
  uint8_t *res_buf = (uint8_t *)calloc(1, 128);

  if (recv(sock, res_buf, 128, 0) <= 0) {
    return -1;
  }

  // parsing
  struct smb_header *res_smb_hdr = (struct smb_header *)(res_buf + 4);

  uint8_t res_command = res_smb_hdr->command;
  uint32_t res_status = res_smb_hdr->status;
  uint16_t res_tid = res_smb_hdr->tid;

  free(res_buf);

  if (res_command == SMB_COM_TREE_CONNECT_ANDX && res_status == 0) {
    return res_tid;
  } else {
    return -1;
  }
}
