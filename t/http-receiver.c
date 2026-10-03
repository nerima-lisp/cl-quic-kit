#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int read_all(int fd, unsigned char *buffer, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = read(fd, buffer + offset, length - offset);
    if (count <= 0) return -1;
    offset += (size_t)count;
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  long expected = strtol(argv[1], NULL, 10);
  int port = (int)strtol(argv[2], NULL, 10);
  int server = socket(AF_INET, SOCK_STREAM, 0);
  if (server < 0) return 1;
  int reuse = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  struct sockaddr_in address = {0};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons((uint16_t)port);
  if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0 ||
      listen(server, 1) < 0) return 1;
  fprintf(stderr, "http-receiver listening port=%d expected=%ld\n", port, expected);
  int client = accept(server, NULL, NULL);
  if (client < 0) return 1;
  fprintf(stderr, "http-receiver accepted\n");
  unsigned char headers[16384];
  size_t used = 0;
  while (used + 1 < sizeof(headers) &&
         !(used >= 4 && !memcmp(headers + used - 4, "\r\n\r\n", 4))) {
    ssize_t count = read(client, headers + used, sizeof(headers) - used - 1);
    if (count <= 0) return 1;
    used += (size_t)count;
    headers[used] = 0;
  }
  if (used < 4 || memcmp(headers, "POST ", 5) != 0) {
    fprintf(stderr, "invalid request line\n");
    return 1;
  }
  char *length_header = strstr((char *)headers, "\r\nContent-Length:");
  if (!length_header) length_header = strstr((char *)headers, "\nContent-Length:");
  if (!length_header) {
    fprintf(stderr, "missing Content-Length\n");
    return 1;
  }
  long length = strtol(strchr(length_header, ':') + 1, NULL, 10);
  if (length != expected || length < 0) {
    fprintf(stderr, "unexpected Content-Length=%ld\n", length);
    return 1;
  }
  char *body = strstr((char *)headers, "\r\n\r\n");
  size_t header_size = (size_t)(body + 4 - (char *)headers);
  long buffered = (long)used - (long)header_size;
  if (buffered > length) {
    fprintf(stderr, "body exceeds Content-Length\n");
    return 1;
  }
  unsigned char buffer[65536];
  if (buffered > 0) {
    for (long i = 0; i < buffered; i++) if (headers[header_size + i] != 0x5a) {
      fprintf(stderr, "invalid body octet at %ld\n", i);
      return 1;
    }
  }
  long remaining = length - buffered;
  while (remaining > 0) {
    size_t count = remaining < (long)sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
    if (read_all(client, buffer, count) < 0) {
      fprintf(stderr, "body ended with %ld bytes remaining\n", remaining);
      return 1;
    }
    for (size_t i = 0; i < count; i++) if (buffer[i] != 0x5a) {
      fprintf(stderr, "invalid body octet\n");
      return 1;
    }
    remaining -= (long)count;
  }
  static const char response[] =
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
  if (write(client, response, sizeof(response) - 1) != (ssize_t)(sizeof(response) - 1))
    return 1;
  fprintf(stderr, "POST length=%ld octets=ok\n", length);
  close(client);
  close(server);
  return 0;
}
