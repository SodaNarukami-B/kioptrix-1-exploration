#include "../../lib/nbios/nbios.h"
#include "../../lib/stdsda/sda.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct payload_t {
  struct nbios_header nb_hdr;
  uint8_t server_name[34];
  uint8_t source_name[34];
} __attribute__((packed));

sda_sp *nbios_send_session_req(int sock) {
  sda_sp *result = (sda_sp *)calloc(1, sizeof(sda_sp));
  if (result == NULL) {
    return NULL;
  }

  // INFO: Payload setting up

  struct payload_t payload;

  // Nbios header
  payload.nb_hdr.type = NBIOS_SESSION_REQ;
  payload.nb_hdr.flag = 0;
  payload.nb_hdr.length = htons(68);

  // Server name
  payload.server_name[0] = 0x20;
  memcpy(payload.server_name + 1, NBIOS_WILD_CARD, 32);
  payload.server_name[33] = 0x00;

  // Source name
  payload.source_name[0] = 0x20;

  const char *raw_source_name = "SODA";

  sda_sp sp_source_name = nbios_htonb(raw_source_name, 4); // Nbios names

  if (sp_source_name.status != 0) {
    free(sp_source_name.buffer);
    printf("- Nbios SS > err: failed to translate data to nbios names\n");
    result->status = -1;
    return result;
  }
  memcpy(payload.source_name + 1, sp_source_name.buffer, sp_source_name.size);
  free(sp_source_name.buffer);

  payload.source_name[33] = 0x00;

  printf("+ Nbios SS > info: payload created\n");

  // INFO: Sending
  if (send(sock, &payload, sizeof(struct payload_t), 0) < 0) {
    printf("- Nbios SS > err: sending failed (connection timeout)\n");

    result->status = -1;
    return result;
  }
  printf("+ Nbios SS > info: payload sended\n");

  // INFO: Receiving
  uint8_t *recv_buffer = (uint8_t *)calloc(1, 4);
  if (recv(sock, recv_buffer, 4, 0) < 0) {
    free(recv_buffer);
    printf("- Nbios SS > err: receiving failed (connection timeout)\n");
    result->status = -1;
    return result;
  }
  printf("+ Nbios SS > info: response received\n");

  // Validating response
  if (recv_buffer[0] != 0x82) {
    printf("- Nbios SS > neg: session denied\n");
    free(recv_buffer);
    result->status = -1;
    return result;
  }

  free(recv_buffer);
  printf("+ Nbios SS > info: session granted\n");

  result->status = 0;
  return result;
}
