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
    memcpy(payload, argv[1], n);

    // ip:port check
    // {0} also sets sin_zero = 0;
    // sin_zero is 8 byte padding for conversion to sockaddr (16 bytes)
    if (parse_target(argv[2], &rs) == -1) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // dns header
    uint16_t id =
        (uint16_t)arc4random();      // get random id (prevents cache poisoning)
    *p++ = (unsigned char)(id >> 8); // 1 byte: id high byte
    *p++ = (unsigned char)(id & 0xff); // 2 byte: id low byte
    // query (0) opcode (0000) aa(0) tc (0) rd (1) -> 0 0000 0 0 1
    *p++ = 0x01; // 3 byte:  flags high byte (query, standard query,
                 //          !authoritive answer, !truncated, recursive)
    // only make sense in response: ra (0) z (000) rcode (0000) -> 0 000 0000
    *p++ = 0x00; // 4 byte:  flags low byte (recursion available,
                 //          reserved bits, response code)
    // question count
    *p++ = 0x00;     // 5 byte: qdcount high byte
    *p++ = 0x01;     // 6 byte: qdcount low byte
    memset(p, 0, 6); // 7 - 12 byte: ancount, nscount, arcount
    p += 6;

    // base32 encode payload
    if (b32enc(b32, MAXB32, payload, n) == 0) {
        fprintf(stderr, "max. payload bytes are %d\n", MAXPAYLOAD);
        return EXIT_FAILURE;
    }

    // payload as qname
    // max 63 chars per label <63 chars>.<63 chars>.t.example.com
    for (size_t i = 0; i < ; i += 63) {
    }

    // dns = udp
    // difference when using udp with connect and without connect
    // - with connect: kernel remebers ip and port of server -> more detailed
    // errors + no packages from other server
    // - without connect: packages from different servers will be accepted
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == 0) {
        fprintf(stderr, "error creating socket\n");
        return EXIT_FAILURE;
    }

    if (connect(fd, (struct sockaddr *)&rs, sizeof rs) == -1) {
        fprintf(stderr, "unable to connect\n");
        return EXIT_FAILURE;
    }

    // timout SO_RCVTIMEO = socket options receive time-out
    struct timeval tv = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}
