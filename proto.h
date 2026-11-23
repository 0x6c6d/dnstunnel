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

int parse_port(const char *str);
int parse_target(const char *target, struct sockaddr_in *out);
size_t b32enc(const unsigned char *in, size_t in_len, uint16_t cap,
              unsigned char *out);

#endif
