// network
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
#pragma pack(push, p1, 1)

struct params_t {
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint8_t reserved;
  uint16_t name_length;
  uint32_t falgs;
  uint32_t root_dfid;
  uint32_t desired_access;
  uint64_t allocation_size;
  uint32_t file_attr;
  uint32_t share_access;
  uint32_t create_disposition;
  uint32_t options;
  uint32_t impersonation_lvl;
  uint8_t security_flags;
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct params_t params;
  uint16_t byte_count;
  uint8_t data_bytes[13];
};

#pragma pack(pop, p1)

int smb_com_nt_create_andx(int sock, uint16_t uid, uint16_t tid) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  packet.nb_hdr.nb_length = htons(sizeof(struct packet_t) - 4);

  memcpy(packet.smb_hdr.protocol, SMB_PROTOCOL, 4);
  packet.smb_hdr.command = SMB_COM_NT_CREATE_ANDX;
  packet.smb_hdr.flag = 0x08;
  packet.smb_hdr.flag2 = 0x0001;
  packet.smb_hdr.tid = tid;
  packet.smb_hdr.uid = uid;

  packet.word_count = 0x18;

  packet.params.andx_command = 0xff;
  packet.params.name_length = 0x0007;
  packet.params.desired_access = 0x02000000;
  packet.params.create_disposition = 0x00000001;
  packet.params.impersonation_lvl = 0x00000002;

  packet.byte_count = 0x0007;

  memcpy(packet.data_bytes, "\\srvsvc", 7);

  /*
  printf("\nREQUEST:\n");
  for (int i = 0; i < sizeof(struct packet_t); i++) {
    printf("%02x%s", *((uint8_t *)&packet + i),
           ((i + 1) % 16 == 0 || i == sizeof(struct packet_t)) ? "\n" : " ");
  }
  */

  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    return -1;
  }

  uint8_t *res = (uint8_t *)calloc(1, 128);

  if (recv(sock, res, 128, 0) <= 0) {
    return -1;
  }

  /*
  printf("\nRESPONSE:\n");
  for (int i = 0; i < 128; i++) {
    printf("%02x%s", res[i], ((i + 1) % 16 == 0 || i == 128) ? "\n" : " ");
  }
 */

  struct smb_header *res_smb_hdr = (struct smb_header *)(res + 4);

  uint8_t res_com = res_smb_hdr->command;
  uint32_t res_stat = res_smb_hdr->status;

  free(res);

  if (res_com == SMB_COM_NT_CREATE_ANDX && res_stat == 0) {
    return 0;
  } else {
    return -1;
  }
}
