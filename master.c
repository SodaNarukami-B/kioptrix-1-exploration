#include "./lib/nbios/nbios.h"
#include "./lib/smb/smb.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
  // INFO: Socket setup
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("- Master: socket error (initialization failed)\n");
    return -1;
  }

  // Socket address
  struct sockaddr_in sa;
  sa.sin_port = htons(139);
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, "192.168.1.104", &sa.sin_addr);

  // Timouts
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 200000;

  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) <
          0 ||
      setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) <
          0) {
    printf("- Master: socket error (timeouts setup error)\n");
    close(sock);
    return -1;
  }

  /////////////////////////////////
  printf("+ Master: socket setup complited\n");
  ////////////////////////////////

  // INFO: Connection
  if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in)) < 0) {
    printf("- Master: connection error\n");
    close(sock);
    return -1;
  }

  printf("+ Master: connected to 192.168.1.104:139\n\n");

  // INFO: Proccessing

  // Net Bios Session Setup
  if (nbios_session_setup(sock) < 0) {
    printf("\n- Master: nbios session setup failed\n");

    close(sock);
    return -1;
  }

  printf("\n+ Master: nbios session granted\n");

  // Smb Negotiation
  if (smb_negotiation(sock) < 0) {
    printf("\n- Master: negotiation failed\n");

    close(sock);
    return -1;
  }

  printf("\n+ Master: negotiation complited successfuly\n");

  // Smb Session Setup
  uint16_t user_id = smb_session_setup(sock);

  if (user_id == 65535) {
    printf("\n- Master: smb session setup failed\n");

    close(sock);
    return -1;
  } else {

    printf("\n+ Master: smb session granted (UID: %d)\n", user_id);

    close(sock);
    return 0;
  }
}
