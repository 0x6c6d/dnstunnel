// arc4random/getrandom need the misc feature set under -std=c11
#define _DEFAULT_SOURCE

#include "proto.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAXPAYLOAD 146
// byte = 2^8, base32 = 2^5
#define MAXB32 ((MAXPAYLOAD * 8 + 4) / 5) // 234: round the last block up

static const char domain[] = "\x01"
                             "t"
                             "\x05"
                             "htons"
                             "\x02"
                             "de"
                             "\x00";

// counts trailing NUL (use -1 to prevent second )
#define DOMLEN (sizeof(domain) - 1)

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
    size_t input_len = strlen(argv[1]);
    if (!input_len || input_len > MAXPAYLOAD) {
        fprintf(stderr, "max. payload bytes are %d\n", MAXPAYLOAD);
        return EXIT_FAILURE;
    }
    memcpy(payload, argv[1], input_len);

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
    *p++ = (unsigned char)(id >> 8); // byte 0: id high byte
    *p++ = (unsigned char)(id & 0xff); // byte 1: id low byte
                                       // query (0) opcode (0000) aa(0) tc (0)
                                       // rd (1) -> 0 0000 0 0 1
    *p++ = 0x01; // byte 2:  flags high byte (query, standard query,
                 // !authoritive answer, !truncated, recursive)
                 // only make sense in response: ra (0) z (000) rcode (0000) ->
                 // 0 000 0000
    *p++ = 0x00; // byte 3:  flags low byte (recursion available,
                 //          reserved bits, response code)
    // question count
    *p++ = 0x00;     // byte 4: qdcount high byte
    *p++ = 0x01;     // byte 5: qdcount low byte
    memset(p, 0, 6); // bytes 6-11: ancount, nscount, arcount
    p += 6;

    // base32 encode payload
    size_t b32_len = b32enc(payload, input_len, MAXB32, b32);
    if (b32_len == 0) {
        fprintf(stderr, "max. payload bytes are %d\n", MAXPAYLOAD);
        return EXIT_FAILURE;
    }

    // payload as qname
    // [len] is 1 byte and [label] is max. 63 bytes
    // <[len1][label1 bytes]>.<[len2][label2 bytes]>.t.example.com
    size_t b32_blocks =
        (b32_len + 62) / 63; // puhses non-zero multiplyer over boundary
    for (size_t i = 0; i < b32_blocks; i++) {
        size_t offset = i * 63;
        size_t len = b32_len - offset;
        if (len > 63)
            len = 63;

        // no dots between labels needed (just presentation for humans - length
        // byte is seperator)
        *p++ = (unsigned char)
            len; // writes [len] (first byte which contains length)
        memcpy(p, b32 + offset, len); // writes [label] to remaining bytes
        p += len;
    }

    // add domain to buffer
    memcpy(p, domain, DOMLEN);
    p += DOMLEN; // advance the cursor, domain already ends in the root label
    *p++ = 0x00;
    *p++ = 16; // qtype txt - big endian 0x0010
    *p++ = 0x00;
    *p++ = 1; // qclass in - 0x0001

    // dns = udp
    // errors + no packages from other server
    // - without connect: packages from different servers will be accepted
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error creating socket\n");
        return EXIT_FAILURE;
    }

    // difference when using udp with connect and without connect
    // - with connect: kernel remebers ip and port of server -> more detailed
    if (connect(fd, (struct sockaddr *)&rs, sizeof rs) == -1) {
        close(fd);
        fprintf(stderr, "unable to connect\n");
        return EXIT_FAILURE;
    }

    // timout SO_RCVTIMEO = socket options receive time-out
    struct timeval tv = {.tv_sec = 1};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    if (sendto(fd, q, (size_t)(p - q), 0, (struct sockaddr *)&rs, sizeof rs) <
        0) {
        close(fd);
        fprintf(stderr, "unable to send\n");
        return EXIT_FAILURE;
    }

    close(fd);
    return 0;
}
