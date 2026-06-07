#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#pragma pack(push, p1, 1)

struct payload_t {
  uint8_t password;
  uint8_t tree_path[21]; // \\192.168.1.104\IPC$\x00
  uint8_t service[4];    // IPC\x00
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct smb_tree_connect_and_x parameters;
  uint16_t byte_count;
  struct payload_t data;
};

uint16_t smb_tree_connect(int sock, uint16_t uid) {
  // INFO: Packet counstructing
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  packet.nb_hdr.length = htons(sizeof(struct packet_t) - 4);

  // Smb Header
  memcpy(&packet.smb_hdr.protocol, SMB_PROTO, 4);
  packet.smb_hdr.command = SMB_TREE_CONNECT;
  packet.smb_hdr.flag = 0x18;
  packet.smb_hdr.flag2 = htole16(0x1002);
  packet.smb_hdr.uid = uid;

  // Word count
  packet.word_count = 0x04;

  // Tree Connect And X
  packet.parameters.andx_command = 0xff;
  packet.parameters.password_len = 0x01;

  // Byte Count
  packet.byte_count = sizeof(struct payload_t);

  // Payload
  memcpy(&packet.data.tree_path, SMB_TREE_PATH, 21);
  memcpy(&packet.data.service, SMB_SERVICE, 4);

  printf("+ Smb tree: packet created\n");

  // INFO: Sending packet
  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    printf("- Smb tree: sending failed (timeout error)\n");
    return -1;
  }

  printf("+ Smb tree: packet sended\n");

  // INFO: Receiving response
  uint8_t *recv_buffer = (uint8_t *)calloc(1, 128);
  int res = recv(sock, recv_buffer, 128, 0);

  if (res < 0) {

    printf("- Smb tree: failed to receive (timeout error)\n");

    free(recv_buffer);
    return -1;

  } else if (res == 0) {

    printf("- Smb tree: connection closed by remote host\n");

    free(recv_buffer);
    return -1;

  } else {
    struct smb_header *recv_smb_hdr = (struct smb_header *)(recv_buffer + 4);

    if (recv_smb_hdr->command == 0x75 && recv_smb_hdr->status == 0) {

      printf("+ Smb tree: access allowed to '\\\\192.168.1.104\\IPC$'\n");
      uint16_t tid = recv_smb_hdr->tid;

      free(recv_buffer);
      return tid;

    } else {

      printf("- Smb tree: access denied (errcode: %08x - reversed)\n",
             recv_smb_hdr->status);

      free(recv_buffer);
      return -1;
    }
  }
}
