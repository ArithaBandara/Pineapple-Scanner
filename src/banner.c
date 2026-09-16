/*
 * banner.c
 * --------
 * Once network.c has confirmed a port is open, this module tries to
 * identify *what* is listening by either:
 *   (a) sending a minimal, well-known protocol probe and reading the
 *       reply (e.g. an HTTP HEAD request), or
 *   (b) simply reading whatever the service volunteers first, since many
 *       protocols (SSH, FTP, SMTP) greet the client unprompted.
 *
 * The socket handed in is already blocking with SO_RCVTIMEO/SO_SNDTIMEO
 * set by network.c, so plain read()/write() here naturally time out
 * instead of hanging - no extra select() bookkeeping needed at this layer.
 */

#include "scanner.h"

#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>

/* Ports where the *client* must speak first before the server replies. */
static bool port_expects_client_probe(int port) {
    switch (port) {
        case 80:
        case 8080:
        case 8000:
        case 443: /* plaintext HEAD won't get a valid TLS reply, but many
                     misconfigured/plain services still sit on 443 */
            return true;
        default:
            return false;
    }
}

/* Sends the appropriate request for known "speak first" ports. */
static void send_probe(int sock, int port, const scan_config_t *cfg) {
    (void)cfg;
    static const char http_head[] =
        "HEAD / HTTP/1.0\r\nHost: scanner\r\nConnection: close\r\n\r\n";

    switch (port) {
        case 80:
        case 8080:
        case 8000:
        case 443: {
            /* Best-effort probe: if the write fails (e.g. peer already
             * closed the connection) the subsequent read() below will
             * simply time out or return 0, which grab_banner() already
             * handles as "(no banner)" - nothing further to do here. */
            ssize_t written = write(sock, http_head, sizeof(http_head) - 1);
            (void)written;
            break;
        }
        default:
            break;
    }
}

/*
 * Collapses a raw response into a single printable line suitable for a
 * results table: strips control characters (CR/LF/tab -> single spaces),
 * collapses runs of whitespace, and trims leading/trailing space.
 */
static void sanitize_banner(char *buf) {
    char cleaned[MAX_BANNER_LEN];
    size_t out = 0;
    bool last_was_space = false;

    for (size_t i = 0; buf[i] != '\0' && out < sizeof(cleaned) - 1; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';

        if (!isprint(c) && c != ' ') continue; /* drop non-printables */

        if (c == ' ') {
            if (last_was_space || out == 0) continue; /* collapse runs */
            last_was_space = true;
        } else {
            last_was_space = false;
        }
        cleaned[out++] = (char)c;
    }
    /* Trim a single trailing space left by the collapse logic. */
    if (out > 0 && cleaned[out - 1] == ' ') out--;
    cleaned[out] = '\0';

    snprintf(buf, MAX_BANNER_LEN, "%s", cleaned);
}

void grab_banner(const scan_config_t *cfg, int sock, int port,
                  char *out, size_t out_len) {
    if (out_len == 0) return;
    out[0] = '\0';

    if (port_expects_client_probe(port)) {
        send_probe(sock, port, cfg);
    }
    /* Otherwise: read immediately. Services like SSH/FTP/SMTP send their
     * banner unsolicited as soon as the TCP handshake completes; the
     * socket's SO_RCVTIMEO (set in network.c) caps how long we'll wait
     * for a service that turns out not to greet at all. */

    char raw[MAX_BANNER_LEN];
    ssize_t n = read(sock, raw, sizeof(raw) - 1);

    if (n > 0) {
        raw[n] = '\0';
        sanitize_banner(raw);
        strncpy(out, raw, out_len - 1);
        out[out_len - 1] = '\0';
    } else {
        /* n == 0: peer closed immediately with no data.
         * n < 0: read timed out (EAGAIN/EWOULDBLOCK) or errored.
         * Either way, we still know the port is open; we just have no
         * banner to report for it. */
        strncpy(out, "(no banner)", out_len - 1);
        out[out_len - 1] = '\0';
    }
}
