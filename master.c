#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, p1, 1)

struct NBIOS_HEADER {
  uint8_t type;
  uint8_t flag;
  uint16_t length;
};

struct SMB_HEADER {
  uint8_t protocol[4];
  uint8_t command;
  uint32_t status;
  uint8_t flag;
  uint16_t flag2;
  uint16_t PID_High;
  uint8_t sign[8];
  uint16_t reserved;
  uint16_t pid;
  uint16_t tid;
  uint16_t uid;
  uint16_t mid;
};

#pragma pack(pop, p1)

int getsock(int timeout) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);

  if (sock < 0) {
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = timeout * 1000;

  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) <
      0) {
    return -1;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) <
      0) {
    return -1;
  }

  return sock;
};

int main() {
  //------------------- SOCKET ---------------------
  int sock = getsock(200);
  if (sock < 0) {
    printf("ERR: socket error\n");
    return -1;
  }

  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = htons(139);
  inet_pton(AF_INET, "192.168.1.104", &sa.sin_addr);
  memset(sa.sin_zero, 0, 8);

  if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr)) < 0) {
    printf("ERR: connection error\n");
    return -1;
  }

  // ------------------ MAIN -----------------------

  uint8_t *buffer = (uint8_t *)calloc(1, 512);
  memset(buffer, 0, 512);

  struct NBIOS_HEADER *nb_hdr = (struct NBIOS_HEADER *)buffer;

  // NBIOS_COM_SESSION_SETUP | 72 bytes
  nb_hdr->type = 0x81;
  nb_hdr->length = htons(68);

  *(buffer + 4) = 0x20;
  memcpy(buffer + 5, "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
  // 37 offset is zero

  *(buffer + 38) = 0x20;
  memcpy(buffer + 39, "EFELEEEAEAEAEAEAEAEAEAEAEAEAEAEA", 32);
  // 67 offset is zero

  if (send(sock, buffer, 68 + 4, 0) < 0) {
    printf("ERR: sending failed (timeout error)\n\t:From "
           "(nbios_session_setup)\n");

    close(sock);
    return -1;
  }

  memset(buffer, 0, 512);

  uint8_t recv_buffer[512];
  int res = recv(sock, recv_buffer, 4, 0);

  if (res < 0) {
    printf("ERR: receiving failed (timeout error)\n\t:From "
           "(nbios_session_setup)\n");

    close(sock);
    return -1;
  } else if (res == 0) {
    printf("ERR: receiving failed (connection closed by remote host)\n\t:From "
           "(nbios_session_setup)\n)");

    close(sock);
    return -1;
  } else {
    if (*recv_buffer != 0x82) {
      printf("ERR: session denied\n\t:From (nbios_session_seutp)\n");

      close(sock);
      return -1;
    }

    // done
  }

  // SMB_COM_NEGOTIATE | 51 bytes

  nb_hdr = (struct NBIOS_HEADER *)buffer;
  struct SMB_HEADER *smb_hdr = (struct SMB_HEADER *)(buffer + 4);

  nb_hdr->length = htons(47);

  memcpy(smb_hdr->protocol, "\xffSMB", 4);
  smb_hdr->command = 0x72;
  smb_hdr->flag = 0x08;
  smb_hdr->flag2 = 0x0001;
  // Predict values
  smb_hdr->uid = 100;
  smb_hdr->tid = 1;

  *(uint16_t *)(buffer + 37) = 0x000c;
  memcpy(buffer + 39, "\x02NT LM 0.12\x00", 12);

  if (send(sock, buffer, 51, 0) < 0) {
    printf(
        "ERR: sending failed (timeout error)\n\t:From (smb_com_negotiate)\n");
    close(sock);
    return -1;
  };

  memset(buffer + 36, 0, 15);
  res = recv(sock, recv_buffer, 512, 0);

  if (res < 0) {
    printf(
        "ERR: receiving failed (timeout error)\n\t:From (smb_com_negotiate)\n");
    close(sock);
    return -1;
  }

  if (res == 0) {
    printf("ERR: receiving failed (connection closed by remote host)\n\t:From "
           "(smb_com_negotiate)\n");
    close(sock);
    return -1;
  }

  if (!(*(recv_buffer + 8) == 0x72 && *((uint32_t *)(recv_buffer + 9)) == 0)) {
    printf("ERR: negotiatie failed\n\t:From (smb_com_negotiate)\n");

    close(sock);
    return -1;
  }

  // SMB_COM_SESSION_SETUP | 68 bytes

  nb_hdr->length = htons(63);
  smb_hdr->command = 0x73;

  uint8_t params[26] = {
      0xff,                   // andx command
      0x00,                   // andx reserved
      0x00, 0x00,             // andx offset
      0xff, 0xff,             // max buffer
      0x01, 0x00,             // max mpx
      0x00, 0x00,             // Virtual channel
      0x00, 0x00, 0x00, 0x00, // Session key
      0x00, 0x00,             // Ansi password length
      0x00, 0x00,             // Uni password length
      0x00, 0x00, 0x00, 0x00, // Reserved
      0x00, 0x00, 0x00, 0x00  // Capabilities
  };

  *(buffer + 36) = 0x0d;
  memcpy(buffer + 37, params, 26);

  *(uint16_t *)(buffer + 63) = 0x0002;

  if (send(sock, buffer, 67, 0) < 0) {
    printf("ERR: sending failed\n\t:From (session_setup)\n");

    close(sock);
    return -1;
  }

  memset(buffer + 36, 0, 31);

  res = recv(sock, recv_buffer, 512, 0);

  if (res < 0) {
    printf("ERR: receiving failed (timeout error)\n\t:From (session_setup)\n");

    close(sock);
    return -1;
  }

  if (res == 0) {
    printf("ERR: receiving failed (connection closed by remote host)\n\t:From "
           "(session_setup)\n");

    close(sock);
    return -1;
  }

  if (!(*(recv_buffer + 8) == 0x73 && *(uint32_t *)(recv_buffer + 9) == 0)) {
    printf("ERR: session failed\n\t:From (session_setup)\n");

    close(sock);
    return -1;
  }

  // TODO: Brutforce trnas2open
}
