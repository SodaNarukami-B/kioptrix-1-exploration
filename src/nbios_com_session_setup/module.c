// Network
#include <arpa/inet.h>
#include <sys/socket.h>

// std
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// custom
#include "../../lib/nbios/nbios.h"
#include "./module_ptr.h"

// Static functions

static uint8_t *nbios_atonb(char *source, size_t source_size) {
  uint8_t *raw_buf = (uint8_t *)calloc(1, 16);
  memset(raw_buf, 0x20, 16);

  strncpy((char *)raw_buf, source, 16);

  uint8_t *buffer = (uint8_t *)calloc(1, 32);

  for (int i = 0; i < 16; i++) {
    buffer[i * 2] = (raw_buf[i] >> 4) + 0x41;
    buffer[i * 2 + 1] = (raw_buf[i] & 0x0f) + 0x41;
  }

  free(raw_buf);

  return buffer;
}

// Static structs

struct packet_t {
  struct nbios_header nb_hdr;
  uint8_t names[68];
} __attribute__((packed));

// compilable code
int nbios_com_session_setup(int sock) {
  // packet creating
  struct packet_t packet;
  memset(&packet, 0, sizeof(struct packet_t));

  packet.nb_hdr.nb_type = NBIOS_COM_SESSION_SETUP;
  packet.nb_hdr.nb_length = htons(68);

  packet.names[0] = 0x20;
  memcpy(packet.names + 1, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);

  packet.names[34] = 0x20;
  uint8_t *source_name = nbios_atonb("SODA", 4);

  memcpy(packet.names + 35, source_name, 32);

  free(source_name);

  /* Debug

   printf("\n");
   for (uint8_t i = 0; i < 68; i++) {
     printf("%02x%s", ((uint8_t *)&packet)[i], ((i + 1) % 16 == 0) ? "\n" : "
   ");
   }
   printf("\n");

   */

  if (send(sock, &packet, sizeof(struct packet_t), 0) < 0) {
    return -1;
  }

  struct nbios_header *res = (struct nbios_header *)calloc(1, 4);

  if (recv(sock, res, 4, 0) <= 0) {
    return -1;
  }
  /* Debug
    for (int i = 0; i < 4; i++) {
      printf("%02x%s", res[i], (i == 3) ? "\n" : " ");
    };
  */

  uint8_t res_type = res->nb_type;
  uint8_t res_flag = res->nb_flag;

  free(res);

  if (res_type == 0x82 && res_flag == 0) {
    return 0;
  } else {
    return -1;
  }
}
