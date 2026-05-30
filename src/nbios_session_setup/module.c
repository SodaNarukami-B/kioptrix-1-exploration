#include "../../lib/nbios/nbios.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

struct payload_t {
  struct nbios_header nb_hdr;
  uint8_t server_name[34];
  uint8_t source_name[34];
} __attribute__((packed));

int nbios_session_setup(int sock) {
  // INFO: Payload counstructing
  struct payload_t payload;

  // NBios header
  payload.nb_hdr.type = NBIOS_SESSION_REQUEST;
  payload.nb_hdr.flag = 0;
  payload.nb_hdr.length = htons(68);

  payload.server_name[0] = 0x20;
  memcpy(payload.server_name + 1, NBIOS_WILDCARD, 32);
  payload.server_name[33] = 0x00;

  payload.source_name[0] = 0x20;
  uint8_t *source_name = nbios_htonb("SODA", 4);
  memcpy(payload.source_name + 1, source_name, 32);
  payload.source_name[33] = 0x00;

  free(source_name);

  printf("+ Nbios session: payload created\n");

  // INFO: Sending payload
  if (send(sock, &payload, sizeof(struct payload_t), 0) < 0) {
    printf("- Niobs session: sending failed\n");
    return -1;
  }

  printf("+ Nibos session: payload sended\n");

  // INFO: Receiving payload
  struct nbios_header recv_nbios_header;

  size_t res = recv(sock, &recv_nbios_header, sizeof(recv_nbios_header), 0);

  if (res < 0) {
    printf("- Nbios session: failed to receive (timeout error)\n");
    return -1;
  } else if (res == 0) {
    printf("- Nbios session: conneciton closed by remote host\n");
    return -1;
  }

  printf("* debug: nbios_header = [");
  for (int i = 0; i < 4; i++) {
    printf("%02x%s", *((uint8_t *)&recv_nbios_header + i),
           (i != 3) ? " " : "]\n");
  }

  if (recv_nbios_header.type == NBIOS_SESSION_GRANTED) {
    printf("+ Nbios session: session granted\n");
    return 0;
  } else if (recv_nbios_header.type == NBIOS_SESSION_DENIED) {
    printf("- Nbios session: session denied (errcode: %d)\n",
           recv_nbios_header.flag);
    return -1;
  } else {
    printf("- Nbios session: respone received but nbios_header.type is unknown "
           "or unexpected (nbios_header.type = %02x)\n",
           recv_nbios_header.type);
    return -1;
  }
}
