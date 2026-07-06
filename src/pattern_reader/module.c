#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_pattern(const char *path, uint8_t *dest, size_t dest_s) {
  FILE *file = fopen(path, "r");

  if (file == NULL) {
    printf("[-] Cant read: file doesn't exists\n");
    return -1;
  };

  fgets((char *)dest, dest_s, file);

  fclose(file);

  return 0;
};
