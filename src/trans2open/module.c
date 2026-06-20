#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#pragma pack(push, p1, 1)

struct payload_t {
  uint8_t name;
  uint8_t pad1[3];
  uint8_t parameter_bytes;
  uint8_t pad2[3];
  uint8_t data_bytes[1032]; // Bad data >:)
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct smb_trans2 param;
  uint16_t byte_count;
  struct payload_t data;
};

#pragma pack(pop, p1)

int smb_trans2open(int sock, uint16_t uid, uint16_t tid) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // Net Bios
  packet.nb_hdr.length = htons(sizeof(struct packet_t) - 4);

  // SMB Header
  memcpy(packet.smb_hdr.protocol, SMB_PROTO, 4);

  packet.smb_hdr.command = SMB_TRANS2;
  packet.smb_hdr.flag = 0x18;
  packet.smb_hdr.flag2 = htole16(0x1002);
  packet.smb_hdr.uid = uid;
  packet.smb_hdr.tid = tid;

  // Word count
  packet.word_count = 0x0f;

  // Parameters
  packet.param.total_data_count = htole16(1032);

  packet.param.parameter_offset = htole16(
      (uint8_t *)&packet.data.parameter_bytes - (uint8_t *)&packet.smb_hdr);

  packet.param.data_count = htole16(1032);
  packet.param.data_offset =
      htole16((uint8_t *)&packet.data.data_bytes - (uint8_t *)&packet.smb_hdr);
  packet.param.setup_count = 1;
  packet.param.setup_words = htole16(0x0001);

  // Byte Count
  packet.byte_count = htole16(sizeof(struct payload_t));

  // WARN: Non complited code. If u see that in commit, commit was indev save
}
