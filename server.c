#include "proto.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void usage(const char *program) {
    fprintf(stderr, "usage: %s [port:optional]\n", program);
}

int main(int argc, char *argv[]) {
    unsigned char q[512], *p = q;

    int port = 5353;
    if (argc > 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        port = parse_port(argv[1]);
        if (port == -1) {
            fprintf(stderr, "invalid port number\n");
            return EXIT_FAILURE;
        }
    }

    // socket
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error creating socket\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    // wildcard addr 0.0.0.0: listen to every IPv4 address this machine has
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    int one = 1;
    // sets option reuseaddr to on (1): tells kernel that new listening sockets
    // can bind regardless of TIME_WAIT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        perror("setsockopt(SO_REUSEADDR)"); // non-fatal
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "error during bind()\n");
        close(fd);
        return EXIT_FAILURE;
    }

    socklen_t alen = sizeof(addr);
    // asks kernel which local address and port the socket is bound to
    // if bind with port 0 kernel picks a free port
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) == 0) {
        printf("listening on udp port %u\n", ntohs(addr.sin_port));
    }

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);

        ssize_t n =
            recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR)
                continue;       // interrupted by signal: retry
            perror("recvfrom"); // anything else: log but dont exit
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        printf("%zd bytes from %s:%u\n", n, ip, ntohs(peer.sin_port));

        // drop silently: prevent amplification attack
        if (n < 12) {
            fprintf(stderr, "no proper header\n");
            continue;
        }

        uint8_t b2 = q[2];
        uint8_t qr = (b2 >> 7) & 0x01;
        uint8_t opcode = (b2 >> 3) & 0x0F;
        uint8_t rd = 0x01;
        if (qr != 0 || opcode != 0) {
            // response and not a query: drop it
            if (qr != 0)
                continue;

            // query is not standard: reply with NOTIMP (RCODE 4)
            send_error(fd, q, 4, &peer, plen);
            continue;
        }

        // QDCOUNT: 16-bit big-endian field at offset [4..5]
        uint16_t qdcount = ((uint16_t)q[4] << 8) | q[5];
        if (qdcount != 1) {
            send_error(fd, q, 1, &peer, plen); // FORMERR
            continue;
        }

        // walk qname
        qname_t qname = {0};
        if (walk_qname(q, (size_t)n, 12, &qname) < 0) {
            send_error(fd, q, 1, &peer, plen); // FORMERR
            continue;
        }
    }

    return 0;
}

/*
 * What actually arrives on the wire (see client.c):
 *   - a single UDP datagram, DNS header + exactly one question, nothing else
 *   - header: 12 bytes
 *       [0..1]  id, random, MUST be echoed back verbatim
 *       [2]     0x01 (QR=0, opcode=0, AA=0, TC=0, RD=1)
 *       [3]     0x00
 *       [4..5]  0x00 0x01 (QDCOUNT=1)
 *       [6..11] 0x00 0x00 0x00 0x00 0x00 0x00 (AN/NS/ARCOUNT=0)
 *   - QNAME: sequence of length-prefixed labels, no compression on the way in
 *       outer labels are the base32 payload, 1..63 bytes each, lowercase
 *       a-z2-7 alphabet, up to 234 chars total split over ceil(n/63) labels
 *       (a full 63-byte label is legal, so do not reject len == 63)
 *       trailer is the fixed suffix "t" "htons" "de" then the root label 0x00
 *   - QTYPE 0x0010 (TXT), QCLASS 0x0001 (IN)
 *   - QNAME is written with explicit length bytes, dots are presentation only,
 *     so parse by lengths, never by strtok/looking for '.'
 *   - base32 has no '=' padding; decode must instead handle the truncated
 *     final block (leftover bits 1..4, zero padded to a 5-bit block)
 *   - response budget is 512 bytes unless you accept EDNS(0) OPT handling
 *
 * Steps:
 *
 *  3. Parse defensively; every read needs a bounds check before it:
 *     - datagram shorter than 12 bytes: no header, drop it
 *     - verify QR == 0 and opcode == 0, otherwise build NOTIMP
 *     - QDCOUNT must be exactly 1, otherwise FORMERR
 *     - ANCOUNT/NSCOUNT/ARCOUNT: ignore the trailing sections if non-zero,
 *       only skip them if you care about EDNS
 *     - walk the QNAME label by label: len byte 1..63, advance len+1, stop at
 *       0x00, count the encoded bytes and abort on overflow, on a length above
 *       63, or when the 255-byte QNAME limit / 12+255 datagram bound is hit
 *     - after the root label you need 4 more bytes for QTYPE/QCLASS, else
 *       FORMERR; require TXT/IN and answer REFUSED for anything else
 *
 *  4. Strip and verify the suffix inside the label list, case-insensitively
 *     (DNS names are case-insensitive, so compare with tolower and leave the
 *     client's case untouched): the last four labels must be t, htons, de, ""
 *     (root). Everything before that is the tunnel payload. If the suffix does
 *     not match, this is not our zone: build REFUSED or forward it.
 *
 *  5. Concatenate the payload labels (length bytes removed) into a scratch
 *     buffer of at least 235 bytes, remembering the true length. Remember:
 *     base32 bloat is 8/5, so 146 payload bytes become 234 characters; a
 *     too-small scratch buffer here is the classic overflow bug.
 *
 *  6. Base32-decode into a payload buffer of at least MAXPAYLOAD (146) bytes:
 *     map a-z to 0..25 and 2-7 to 26..31, reject anything else (FORMERR),
 *     shift 5 bits into an accumulator per character, emit a byte every 8
 *     bits. Throw the accumulator away at the end: the last block carries
 *     1..4 padded bits that produce no whole byte. Watch out for a trailing
 *     block that is one character long and encodes fewer than 8 bits. Size
 *     the output check against MAXPAYLOAD before every emit.
 *
 *  7. Decide what goes back. Minimum viable: echo the datagram's id, set
 *     QR=1, keep RD, copy the client's opcode, RCODE 0 (NOERROR), AA=1, and
 *     answer with QDCOUNT 1 / ANCOUNT 1 -- and optionally log the decoded
 *     payload plus TTL/TXID so you can see the message arriving. Common
 *     alternatives: RCODE 3 (NXDOMAIN) for unknown suffixes, RCODE 5
 *     (REFUSED) for a bad suffix, FORMERR on malformed input, and TC=1 if the
 *     answer cannot fit in 512 bytes.
 *
 *  8. Build the response into a separate 512-byte buffer, never in place over
 *     the request:
 *     - copy the 12-byte request header
 *     - set the QR bit and flags as decided in step 7
 *     - then re-emit the question section EXACTLY as received (QNAME bytes,
 *       QTYPE, QCLASS, same case) so the client matches the reply to its
 *       query; a mismatching or compressed-away question gets replies dropped
 *     - answer record: NAME as the compression pointer 0xC0 0x0C (backwards
 *       to the question name at offset 12), TYPE 16, CLASS 1, a TTL (keep it
 *       low, e.g. 0 or 60, otherwise resolvers cache and your next message
 *       stalls), RDLENGTH, then one or more length-prefixed TXT character
 *       strings. If the answer exceeds 255 bytes split it over several
 *       character strings, each still length-prefixed.
 *     - if the assembled response crosses 512 bytes, either trim the TXT
 *       data or flip TC and drop the answer section
 *
 *  9. sendto() the response back to the exact peer sockaddr_in that
 *     recvfrom() reported, with the response length you actually built (not
 *     buffer or header sizes). Then go back to step 2; one datagram in, one
 *     datagram out, no state needs to survive the iteration.
 *
 * 10. Test before trusting it: dig from the command line
 *     (`dig @127.0.0.1 -p <port> TXT <base32>.t.htons.de`) to check parsing
 *     and the TXT answer, then run client.c itself and diff what the server
 *     logged against the argument you passed. Fuzz the parser by hand with
 *     `dig` on odd names, oversize labels and non-TXT QTYPEs; then run
 *     under -fsanitize=address,undefined while feeding it garbage.
 *
 * Gotchas from the existing code you should mirror instead of re-inventing:
 *   - proto.c's b32enc alphabet is lowercase a-z2-7, so the decoder maps the
 *     same set; uppercase input only appears if a resolver re-cases it, which
 *     makes case-insensitive suffix compare worth the two lines
 *   - parse_target() in proto.c is ip:port (client side); your server takes a
 *     port only, so either reuse parse_port semantics or bind a fixed port
 *   - the client sets SO_RCVTIMEO to 1s and never reads the reply, so the
 *     round trip must complete inside a second
 *   - the 255-byte QNAME limit is why MAXPAYLOAD is 146 bytes (234 chars +
 *     suffix); do not raise it without also fixing the label split
 */
