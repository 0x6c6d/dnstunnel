#include "proto.h"
#include <stdint.h>

static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

static int parse_ip(const char *str, struct in_addr *out) {
    return inet_pton(AF_INET, str, out) == 1;
}

static int parse_port(const char *str) {
    char *end;
    errno = 0;
    long port = strtol(str, &end, 10);

    if (errno != 0 || str == end || *end != '\0' || port < 1 || port > 65535) {
        return -1;
    }

    return (int)port;
}

int parse_target(const char *target, struct sockaddr_in *out) {
    // target = ip:port, sizeof(char) = 1

    // check if form is valid (ip:port)
    const char *colon = strchr(target, ':');
    if (!colon || strchr(colon + 1, ':')) {
        return -1;
    }

    // check if ip is valid
    size_t ip_len = (size_t)(colon - target);
    if (ip_len == 0 || ip_len > INET_ADDRSTRLEN) {
        return -1;
    }

    char ip_str[INET_ADDRSTRLEN];
    memcpy(ip_str, target, ip_len);
    ip_str[ip_len] = '\0';

    struct in_addr ip;
    if (!parse_ip(ip_str, &ip)) {
        return -1;
    }

    // check port
    char port_str[6];
    size_t port_len = strlen(colon + 1);
    memcpy(port_str, colon + 1, port_len);
    port_str[port_len] = '\0';
    int port = parse_port(port_str);
    if (port == -1) {
        return -1;
    }

    // sockaddr_in struct
    *out = (struct sockaddr_in){.sin_family = AF_INET,
                                .sin_addr = ip,
                                .sin_port = htons((uint16_t)port)};

    return 0;
}

size_t b32enc(const unsigned char *in, size_t in_len, uint16_t cap,
              unsigned char *out) {
    if (in_len == 0 || in_len > (size_t)cap)
        return 0;

    // dns has LDH rule (letters, digits, hyphens)
    // no '=' as padding char allowed + unnecessary overhead

    // Hi -> ASCII: 72 105 -> 01001000 01101001
    // in = 2 chars = 2 byte = 16 bit -> needs 4 blocks a 5 bit (16 fit into 20)
    // 5 bit blocks: 01001 00001 10100 10000
    // 5 bit blocks:   J     B     U     Q

    uint32_t buf = 0;
    int bits = 0;
    size_t o = 0;

    for (int i = 0; i < in_len; i++) {
        // push 8 empty bits into buffer (buf << 8) and write bits from input
        // into it with OR operation (| in[i])
        buf = (buf << 8) | in[i];
        bits += 8;

        // iterate over as many 5 bit blocks as the buffer holds
        while (bits >= 5) {
            // buf >> (bits - 5): move most left (oldest) 5 bits to the right
            // (newest) & 0x1F: mask with 000 11111 (only lowest 5 bits of byte
            // stay) B32[]: look up char from b32 alphabet and add it to out
            out[o++] = B32[(buf >> (bits - 5)) & 0x1f];
            bits -= 5;
        }
    }

    if (bits > 0) {
        // pad the leftover bits (1-4) to the rigt
        out[o++] = B32[buf << (5 - bits) & 0x1F];
    }

    return o;
}
