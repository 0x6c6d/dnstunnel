#include "proto.h"

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

size_t b32enc(unsigned char *dst, size_t cap, const unsigned char *src,
              size_t n) {
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz234567";
    size_t o = 0;

    // walk input in 5 byte blocks
    for (size_t i = 0; i < n; i += 5) {
        // block size: 1-5 (only the last block can be 5 or smaller)
        size_t bs = n - i < 5 ? n - i : 5;
        uint64_t v = 0;
        // find characters a block needs ()
        int chars = ((int)bs * 8 + 4) / 5;
    }

    return o;
}
