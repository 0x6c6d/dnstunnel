#include "proto.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define MAXPAYLOAD 150
// Byte = 2^8, Base32 = 2^5
#define MAXB32 (MAXPAYLOAD * 8 / 5)

static void usage(const char *program) {
    fprintf(stderr, "usage: %s <payload> <ip:port>\n", program);
}

int main(int argc, char *argv[]) {
    unsigned char payload[MAXPAYLOAD], b32[MAXB32];
    struct sockaddr_in rs;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <payload> <port>", argv[0]);
        return EXIT_FAILURE;
    }

    int port = parse_port(argv[2]);
    if (port == -1) {
        fprintf(stderr, "invalid port: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    // payload check
    size_t n = strlen(argv[1]);

    if (!n || n > MAXPAYLOAD) {
        fprintf(stderr, "max. payload bytes are %d\n", MAXPAYLOAD);
        return EXIT_FAILURE;
    }

    // {0} also sets sin_zero = 0;
    // sin_zero is 8 byte padding for conversion to sockaddr (16 bytes)
    struct sockaddr_in rs = {0};
    rs.sin_family = AF_INET;
    rs.sin_port = htons(port);
    // LOOPBACK = 127.0.0.1
    // in reality it goes to /etc/resolv.conf, e.g. Fritz!Box
    rs.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // dns = udp
    // difference when using udp with connect and without connect
    // - with connect: kernel remebers ip and port of server -> more detailed
    // errors + no packages from other server
    // - without connect: packages from different servers will be accepted
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (connect(fd, (struct sockaddr *)&rs, sizeof rs) == -1) {
        fprintf(stderr, "unable to connect\n");
    }

    // timout SO_RCVTIMEO = socket options receive time-out
    struct timeval tv = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    // dns anfrage -> <base32>.t.example.com
}
