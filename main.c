#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main() {
  // INFO: Socket setting up

  // Socket initialization
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    printf("[-] Main > socket error\n");
    return -1;
  }

  // Creating & setting up socket address
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(struct sockaddr_in));

  sa.sin_family = AF_INET;
  if (inet_pton(AF_INET, "192.168.1.24", &sa.sin_addr) < 0) {
    printf("[-] Main > config error (cannot set address)\n");
    return -1;
  }

  sa.sin_port = htons(139);

  // Setting up timeouts
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 200000;

  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));

  printf("[+] Main > socket created and configured\n");

  // INFO: Connection
  if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0) {
    printf("[-] Main > failed to connect\n");
    return -1;
  }
  printf("[+] Main > connected\n");
