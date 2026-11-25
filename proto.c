#include "proto.h"
#include <stdint.h>

static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

static int parse_ip(const char *str, struct in_addr *out) {
    return inet_pton(AF_INET, str, out) == 1;
}

int parse_port(const char *str) {
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
    if (ip_len == 0 || ip_len >= INET_ADDRSTRLEN) {
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
    int port = parse_port(colon + 1);
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

    for (size_t i = 0; i < in_len; i++) {
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

/*
 * QNAME walk: example packet, n = 56
 * qname = nbswy3dpebsg44zaor2w43tfnq.t.htons.de  (b32 of "hello dns tunnel")
 *
 *   offset  0           11 12 13..32 33 34..39 40 41 42 43..47 48 49..50
 * 51 52..53 54..55
 *          +--------------+--+------+--+------+--+--+--+------+--+------+--+------+------+
 *          | header (12B) |14| 20 B |06| 6 B  |01| t|05|htons |02|  de
 * |00|QTYPE |QCLASS|
 *          +--------------+--+------+--+------+--+--+--+------+--+------+--+------+------+
 *                          ^         ^         ^     ^          ^        ^
 *                        pos=12    pos=33    pos=40 pos=42    pos=48   pos=51
 * (root)
 *
 * every label is [len][len bytes]; the next label starts at pos + 1 + len:
 *
 *   pos=12  len=20  "nbswy3dpebsg44zaor2w"  -> pos = 12 + 1 + 20 = 33
 *   pos=33  len= 6  "43tfnq"                -> pos = 33 + 1 +  6 = 40
 *   pos=40  len= 1  "t"                     -> pos = 40 + 1 +  1 = 42
 *   pos=42  len= 5  "htons"                 -> pos = 42 + 1 +  5 = 48
 *   pos=48  len= 2  "de"                    -> pos = 48 + 1 +  2 = 51
 *   pos=51  len= 0  root, stop              -> pos = 52 (QTYPE starts here)
 *
 * result of the walk:
 *   labels[0] = {off 13, len 20}  payload  \ concatenate in step 5
 *   labels[1] = {off 34, len  6}  payload  /
 *   labels[2] = {off 41, len  1}  "t"      \
 *   labels[3] = {off 43, len  5}  "htons"   > suffix, checked in step 4
 *   labels[4] = {off 49, len  2}  "de"     /
 *   end       = 52                where QTYPE/QCLASS begin
 *   name size = 40 encoded bytes (length bytes + labels + root), limit 255
 */
int walk_qname(const uint8_t *pkt, size_t n, size_t start, qname_t *out) {
    size_t pos = start;
    size_t total = 0;
    out->count = 0;

    for (;;) {
        // is there a length byte to read?
        // n: sizeof q (bytes received)
        if (pos >= n) {
            return -1;
        }

        uint8_t len = pkt[pos];

        if (len == 0) {
            // end is meant to be where qtype starts
            out->end = pos + 1;
            return 0;
        }

        // max. label length can be 63
        if (len > 63) {
            return -1;
        }

        // labels last byte must lie inside received bytes
        // pos + 1 (label start byte) + (label len) > bytes received
        if (pos + 1 + len > n) {
            return -1;
        }

        // name cant exceed 255 bytes (254 because 1 byte is reserved
        // for the root byte)
        // + 1: label's length byte
        if (total + len + 1 > 254) {
            return -1;
        }

        // struct can only store 16 labels
        if (out->count > 15) {
            return -1;
        }

        out->items[out->count++] = (label_t){(uint16_t)(pos + 1), len};
        total += 1 + len;
        pos += 1 + len;
    }

    return 0;
}

void send_error(int fd, const unsigned char *q, uint8_t rcode,
                const struct sockaddr_in *peer, socklen_t plen) {
    unsigned char r[12] = {0};
    r[0] = q[0];
    r[1] = q[1];
    r[2] = 0x80 | (q[2] & 0x78) | (q[2] & 0x01); // QR=1, echo opcode and RD
    r[3] = rcode;
    sendto(fd, r, sizeof r, 0, (const struct sockaddr *)peer, plen);
}
