#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// Data bytes in NT Create is just buffer of name

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct smb_nt_create_andx parameters;
  uint16_t byte_count;
  uint8_t name[8];
} __attribute__((packed));

uint16_t smb_nt_create(int sock, uint16_t uid, uint16_t tid) {
  // INFO: Packet building
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // Net Bios
  packet.nb_hdr.length = htons(sizeof(struct packet_t) - 4);

  // Smb Header
  memcpy(&packet.smb_hdr.protocol, SMB_PROTO, 4);
  packet.smb_hdr.command = SMB_NT_CREATE;
  packet.smb_hdr.flag = 0x18;
  packet.smb_hdr.flag2 = htole16(0x1002);
  packet.smb_hdr.tid = tid;
  packet.smb_hdr.uid = uid;

  // Word Count
  packet.word_count = 24;

  // Parameters (Nt Create And X)
  packet.parameters.andx_command = 0xff;
  packet.parameters.name_length = htole16(7);
  packet.parameters.desired_access = htole32(0x02000000);
  packet.parameters.share_access = htole32(7);
  packet.parameters.create_disposition = htole32(1);
  packet.parameters.create_options = htole32(4);
  packet.parameters.impersonation_level = htole32(2);
  packet.parameters.security_flags = htole32(1);

  // Byte Count
  packet.byte_count = htole16(5);

  // Data Bytes
  memcpy(packet.name, "\\ntsvcs", 8);

  printf("+ NT Create: packet created\n");

  // INFO: Sending packet
  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    printf("- NT Create: Sending failed (timeout error)\n");
    return -1;
  }

  printf("+ NT Create: Packet sended\n");

  uint8_t *recv_buffer = (uint8_t *)calloc(1, 128);
  int res = recv(sock, recv_buffer, 128, 0);

  if (res < 0) {
    printf("- NT Create: Receiving failed (timeout error)\n");
    free(recv_buffer);

    return -1;
  } else if (res == 0) {
    printf("- NT Create: Connection closed by remote host\n");
    free(recv_buffer);

    return -1;
  } else {
    struct smb_header *recv_header = (struct smb_header *)(recv_buffer + 4);

    if (recv_header->command == SMB_NT_CREATE && recv_header->status == 0) {
      printf("+ NT Create: File created successfuly\n");

      uint16_t fid = *(uint16_t *)(recv_buffer + 4 + 32 + 1 + 5);

      free(recv_buffer);
      return fid;
    } else {
      printf("- NT Create: Filed to create file (err code: %08x - reversed)",
             recv_header->status);

      free(recv_buffer);
      return -1;
    }
  }
}
