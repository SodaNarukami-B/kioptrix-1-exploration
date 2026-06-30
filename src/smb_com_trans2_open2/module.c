#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include "./module_ptr.h"

#pragma pack(push, 1)

struct params_t {
  uint16_t total_parameter_count;
  uint16_t total_data_count;
  uint16_t max_parameter_count;
  uint16_t max_data_count;
  uint8_t max_setup_count;
  uint8_t pad;
  uint16_t flags;
  uint32_t timeout;
  uint16_t reserved;
  uint16_t parameter_count;
  uint16_t parameter_offset;
  uint16_t data_count;
  uint16_t data_offset;
  uint8_t setup_count;
  uint8_t pad2;
  uint16_t setup_word;
};

struct open2_t {
  uint16_t flags;
  uint16_t access_mode;
  uint16_t reserved;
  uint16_t file_attr;
  uint32_t creation_time;
  uint16_t open_mode;
  uint32_t allocation_size;
  uint8_t reserved2[10];
  uint8_t file_name[4000];
};

struct data_bytes_t {
  uint8_t name;
  uint8_t pad[3];
  struct open2_t open2;
  uint8_t pad2[4];
  uint8_t trans2_data_bytes;
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct params_t params;
  uint16_t byte_count;
  struct data_bytes_t data_bytes;
};

#pragma pack(pop, 1)

int smb_com_trans2_open2(int sock, uint16_t tid, uint16_t uid) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  packet.nb_hdr.nb_length = htons(sizeof(struct packet_t) - 4);

  memcpy(packet.smb_hdr.protocol, "\xffSMB", 4);
  packet.smb_hdr.command = 0x32;
  packet.smb_hdr.flag = 0x08;
  packet.smb_hdr.flag2 = 0x0001;
  packet.smb_hdr.tid = tid;
  packet.smb_hdr.uid = uid;

  packet.params.parameter_count = htons(4000);
  packet.params.parameter_offset =
      (uint8_t *)&packet.data_bytes.open2 - (uint8_t *)&packet.smb_hdr;
  packet.params.data_offset =
      (uint8_t *)&packet.data_bytes.open2.file_name[12] -
      (uint8_t *)&packet.smb_hdr;

  // TODO: [ ] Setup params, setup open2
};
