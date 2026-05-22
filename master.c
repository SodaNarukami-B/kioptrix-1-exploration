#include "./lib/nbios/nbios.h"
#include "./lib/smb/smb.h"
#include "./lib/stdsda/sda.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

int main(int argc, char *argv[]) {

  printf("+ Master > status: started\n");

  if (argc != 3) {
    printf(
        "- Master > err: invalid input\n( usage: master [address] [port] )\n");
    return -1;
  }

  // INFO: Socket & Socket address & Timeouts

  // INFO: Socket initialization
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("- Master > err: socket error\n");
    return -1;
  }
  printf("+ Master > info: socket created\n");

  // INFO: Socket address setting up
  struct sockaddr_in socket_address;
  socket_address.sin_family = AF_INET;
  if (inet_pton(AF_INET, argv[1], &socket_address.sin_addr) < 0) {
    printf("- Master > err: invalid address (use IPv4 format)\n");
    return -1;
  }

  char *str_port = argv[2];
  char *endptr = NULL;

  long port = strtol(str_port, &endptr, 10);
  if (endptr == str_port) {
    printf("- Master > err: invalid port\n");
    return -1;
  }

  socket_address.sin_port = htons(port);

  // INFO: Timeouts
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 200000;

  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) <
      0) {
    printf("- Master > err: timeout setting error (SNDTIMEO)\n");
    return -1;
  }
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) <
      0) {
    printf("- Master > err: timeout setting error (RCVTIMEO)\n");
    return -1;
  }

  printf("+ Master > info: socket configurated successfuly\n");

  if (connect(sock, (struct sockaddr *)&socket_address,
              sizeof(struct sockaddr)) < 0) {
    printf("- Master > err: failed to connect\n");
    return -1;
  }
  printf("+ Master > info: connected to %s:%s\n\n", argv[1], argv[2]);

  // INFO: Actions

  // INFO: Step 1: Net Bios session setup
  sda_sp *nbios_session_results = nbios_send_session_req(sock);

  if (nbios_session_results->status != 0) {
    printf("\n- Master > err: step 1 (nbios session setup) failed\n");
    free(nbios_session_results);
    return -1;
  }

  free(nbios_session_results);
  printf("\n+ Master > info: step 1 (nbios session setup) complited "
         "successfuly\n\n");

  // INFO: Step 2: Samba > negtionation
  sda_sp *smb_negotiation_results = smb_send_negotiation(sock);

  if (smb_negotiation_results->status != 0) {
    printf("\n- Master > err: step 2 (smb negotiation) failed\n");
    free(smb_negotiation_results);
    return -1;
  }

  free(smb_negotiation_results);
  printf(
      "\n+ Master > info: step 2 (smb negotiation) complited successfuly\n\n");

  return 0;
}
