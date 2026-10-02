#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void stop_proxy(int signal_number) {
  (void)signal_number;
  stop_requested = 1;
}

static int parse_port(const char *text) {
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (!*text || (end && *end) || value < 1 || value > 65535)
    return -1;
  return (int)value;
}

static int parse_nonnegative(const char *text) {
  char *end = NULL;
  long value = strtol(text, &end, 10);
  if (!*text || (end && *end) || value < 0 || value > 2147483647)
    return -1;
  return (int)value;
}

static int parse_percentage(const char *text) {
  int value = parse_nonnegative(text);
  return value >= 0 && value <= 100 ? value : -1;
}

static bool same_address(const struct sockaddr_in *left,
                         const struct sockaddr_in *right) {
  return left->sin_family == right->sin_family &&
         left->sin_port == right->sin_port &&
         left->sin_addr.s_addr == right->sin_addr.s_addr;
}

int main(int argc, char **argv) {
  if (argc < 4 || argc > 6) {
    fprintf(stderr,
            "usage: %s LISTEN_PORT UPSTREAM_PORT DROP_SERVER_PACKETS "
            "DROP_SERVER_PERCENT MUTATE_1RTT\n",
            argv[0]);
    return 2;
  }
  int listen_port = parse_port(argv[1]);
  int upstream_port = parse_port(argv[2]);
  int drops_remaining = parse_nonnegative(argv[3]);
  int drop_percent = argc >= 5 ? parse_percentage(argv[4]) : 0;
  int mutate_1rtt = argc >= 6 ? parse_nonnegative(argv[5]) : 0;
  if (listen_port < 0 || upstream_port < 0 || drops_remaining < 0 ||
      drop_percent < 0 || mutate_1rtt < 0 || mutate_1rtt > 1) {
    fputs("invalid UDP proxy argument\n", stderr);
    return 2;
  }

  int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    perror("socket");
    return 1;
  }
  int reuse = 1;
  (void)setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in listen_address;
  memset(&listen_address, 0, sizeof(listen_address));
  listen_address.sin_family = AF_INET;
  listen_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  listen_address.sin_port = htons((uint16_t)listen_port);
  if (bind(socket_fd, (struct sockaddr *)&listen_address,
           sizeof(listen_address)) < 0) {
    perror("bind");
    close(socket_fd);
    return 1;
  }

  struct sockaddr_in upstream_address;
  memset(&upstream_address, 0, sizeof(upstream_address));
  upstream_address.sin_family = AF_INET;
  upstream_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  upstream_address.sin_port = htons((uint16_t)upstream_port);
  struct sockaddr_in client_address;
  memset(&client_address, 0, sizeof(client_address));
  bool have_client = false;

  signal(SIGINT, stop_proxy);
  signal(SIGTERM, stop_proxy);
  unsigned char buffer[65536];
  unsigned long server_packets = 0;
  bool mutated_1rtt = false;
  fprintf(stderr,
          "udp-proxy listening on 127.0.0.1:%d -> 127.0.0.1:%d "
          "loss=%d%% mutate-1rtt=%d\n",
          listen_port, upstream_port, drop_percent, mutate_1rtt);
  while (!stop_requested) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(socket_fd, &read_set);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 250000};
    int ready = select(socket_fd + 1, &read_set, NULL, NULL, &timeout);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      perror("select");
      break;
    }
    if (!ready)
      continue;

    struct sockaddr_in source_address;
    socklen_t source_length = sizeof(source_address);
    ssize_t received = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&source_address,
                                 &source_length);
    if (received < 0) {
      if (errno == EINTR)
        continue;
      perror("recvfrom");
      break;
    }
    if (same_address(&source_address, &upstream_address)) {
      if (!have_client)
        continue;
      ++server_packets;
      bool percentage_drop = drop_percent > 0 &&
                             ((server_packets * 37u) % 100u) <
                                 (unsigned int)drop_percent;
      if (drops_remaining > 0 || percentage_drop) {
        if (drops_remaining > 0)
          --drops_remaining;
        fprintf(stderr,
                "udp-proxy dropped server packet (%zd bytes), %d left "
                "(%d%% schedule)\n",
                received, drops_remaining, drop_percent);
        continue;
      }
      if (mutate_1rtt && !mutated_1rtt && received > 20 &&
          (buffer[0] & 0x80u) == 0) {
        buffer[received - 1] ^= 1;
        mutated_1rtt = true;
        fprintf(stderr, "udp-proxy mutated server 1-rtt packet (%zd bytes)\n",
                received);
      }
      if (sendto(socket_fd, buffer, (size_t)received, 0,
                 (struct sockaddr *)&client_address,
                 sizeof(client_address)) < 0)
        perror("sendto client");
    } else {
      client_address = source_address;
      have_client = true;
      if (sendto(socket_fd, buffer, (size_t)received, 0,
                 (struct sockaddr *)&upstream_address,
                 sizeof(upstream_address)) < 0)
        perror("sendto upstream");
    }
  }
  close(socket_fd);
  return 0;
}
