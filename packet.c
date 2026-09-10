#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma pack(push, 1)

// RESERVED
typedef struct {
  uint8_t type;
  uint8_t flags;
  uint16_t len;
} NBHDR;

// RESERVED
typedef struct {
  uint8_t protocol[4];
  uint8_t command;
  uint8_t flags;
  uint16_t flags2;
  uint16_t pid_h;
  uint8_t secure[8];
  uint16_t reserved;
  uint16_t tid;
  uint16_t pid_l;
  uint16_t uid;
  uint16_t mid;
} SMBHDR;

#pragma pack(pop)

// Special not secure
int nbios_htonb(uint8_t *data, uint8_t *out) {
  for (int i = 0; i < 16; i++) {
    out[i * 2] = (data[i] >> 4) + 0x41;
    out[i * 2 + 1] = (data[i] & 0x0f) + 0x41;
  };

  return 0;
};

void usage() { printf("Usage: /path/to/binary [packet]\nPakets:\n\t- 1: netbios session setup request\n"); };

void get_nbss_x81() {
  uint8_t nbios_session[72] = "\x81"      // type
                              "\x00"      // flag
                              "\x00\x44"; // len
  nbios_session[4] = 0x20;
  nbios_session[37] = 0x00;
  nbios_session[38] = 0x20;
  nbios_session[71] = 0x00;

  uint8_t wild_card[32] = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  memcpy(nbios_session + 5, wild_card, 32);

  uint8_t client_name[16] = "SODA\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";

  nbios_htonb(client_name, nbios_session + 39);

  printf(" --- Netbios Session Setup: Request packet ---\n");

  for (int i = 0; i < 72; i++) {
    printf("\\x%02x%s", *(nbios_session + i), ((i + 1) % 12 == 0 || (i + 1) == 72) ? "\n" : "");
  };
};

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  };

  if (strcmp(argv[1], "1") == 0) {
    get_nbss_x81();
    return 0;
  };

  usage();
  return 0;
};
