// Network
#include <arpa/inet.h>
#include <sys/socket.h>

// Std
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// custom
#include "../../lib/nbios/nbios.h"
#include "../../lib/smb/smb.h"
#include "./module_ptr.h"

// structs
#pragma pack(push, p1, 1)

struct parameters_t {
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint16_t max_buffer;
  uint16_t max_mpx;
  uint16_t vc;
  uint32_t session_key;
  uint16_t ansi_password_len;
  uint16_t uni_password_len;
  uint32_t reserved;
  uint32_t capabilities;
};

struct packet_t {
  struct nbios_header nb_hdr;
  struct smb_header smb_hdr;
  uint8_t word_count;
  struct parameters_t params;
  uint16_t byte_count;
  uint8_t data_buffer[17];
};

#pragma pack(pop, p1)

short smb_com_session_setup_andx(int sock) {
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  // Net Bios
  packet.nb_hdr.nb_length = htons(sizeof(struct packet_t) - 4);

  // Smb header
  memcpy(packet.smb_hdr.protocol, SMB_PROTOCOL, 4);
  packet.smb_hdr.command = SMB_COM_SESSION_SETUP_ANDX;
  packet.smb_hdr.flag = 0x08;
  packet.smb_hdr.flag2 = 0x0001;

  // Word count
  packet.word_count = 13;

  // Parameters
  packet.params.andx_command = 0xff;
  packet.params.max_buffer = 0xffff;
  packet.params.max_mpx = 0x0001;
  packet.params.ansi_password_len = 0x0001;
  packet.params.uni_password_len = 0x0001;

  // Byte count
  packet.byte_count = 0x000f;

  // Data bytes
  memcpy(&packet.data_buffer[3], "SODA", 5);
  memcpy(&packet.data_buffer[9], "MYGROUP", 8);

  // memcpy(&packet.data_buffer[3], "MYGROUP", 8); // if data_buffer size is 11

  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    return -1;
  }

  uint8_t *res = (uint8_t *)calloc(1, 128);

  if (recv(sock, res, 128, 0) <= 0) {
    return -1;
  }

  struct smb_header *res_smb_hdr = (struct smb_header *)(res + 4);

  uint8_t res_command = res_smb_hdr->command;
  uint32_t res_status = res_smb_hdr->status;
  uint16_t uid = res_smb_hdr->uid;

  if (res_command == SMB_COM_SESSION_SETUP_ANDX && res_status == 0) {
    return uid;
  } else {
    return -1;
  }
}
