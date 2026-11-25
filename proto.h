#ifndef PROTO_H
#define PROTO_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef struct {
    uint16_t off;
    uint8_t len;
} label_t;

typedef struct {
    label_t items[16];
    size_t count;
    size_t end;
} qname_t;

int parse_port(const char *str);
int parse_target(const char *target, struct sockaddr_in *out);
size_t b32enc(const unsigned char *in, size_t in_len, uint16_t cap,
              unsigned char *out);
int walk_qname(const uint8_t *pkt, size_t n, size_t start, qname_t *out);
void send_error(int fd, const unsigned char *q, uint8_t rcode,
                const struct sockaddr_in *peer, socklen_t plen);

#endif
