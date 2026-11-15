#include "proto.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXPAYLOAD 150
// Byte = 2^8, Base32 = 2^5
#define MAXB32 (MAXPAYLOAD * 8 / 5)

static void usage(const char *program) {
    fprintf(stderr, "usage: %s <payload> <ip:port>\n", program);
}

int main(int argc, char *argv[]) {
    unsigned char payload[MAXPAYLOAD], b32[MAXB32];
    unsigned char q[512], *p = q;
    struct sockaddr_in rs = {0};

    if (argc != 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // payload check
    size_t n = strlen(argv[1]);

    if (!n || n > MAXPAYLOAD) {
        fprintf(stderr, "max. payload bytes are %d\n", MAXPAYLOAD);
        return EXIT_FAILURE;
    }

    // ip:port check
    // {0} also sets sin_zero = 0;
    // sin_zero is 8 byte padding for conversion to sockaddr (16 bytes)
    if (parse_target(argv[2], &rs) == -1) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

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

    // dns header
    uint16_t id = (uint16_t)getpid();
    *p++ = (unsigned char)(id >> 8);
    *p++ = (unsigned char)(id & 0xff);
    *p++ = 0x01;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x01;
    memset(p, 0, 6);
    p += 6;
}
