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
size_t b32enc(unsigned char *dst, size_t cap, const unsigned char *src,
              size_t n);

#endif
