/*
 * network.c
 * ---------
 * Non-blocking TCP connect with a select()-driven timeout.
 *
 * Why non-blocking + select() instead of a plain blocking connect()?
 * A blocking connect() to a *filtered* port (one behind a firewall that
 * silently drops packets) can hang for the OS's full TCP timeout, which
 * is commonly 30-120+ seconds. With hundreds of ports and only a few tens
 * of worker threads, a handful of filtered ports would stall the whole
 * scan. Setting the socket non-blocking makes connect() return
 * immediately with EINPROGRESS, and select() lets us enforce our own,
 * much shorter deadline while still being notified the instant the
 * connection actually completes (successfully or not).
 */

#include "scanner.h"

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

/* Puts `fd` into non-blocking mode. Returns 0 on success, -1 on failure. */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

port_state_t probe_port(const scan_config_t *cfg, int port, int *out_sock) {
    *out_sock = -1;

    int sock = socket(cfg->family, SOCK_STREAM, 0);
    if (sock < 0) {
        /* Out of file descriptors or similar transient condition: treat
         * as filtered/unknown rather than crashing the whole scan. */
        return PORT_FILTERED;
    }

    if (set_nonblocking(sock) < 0) {
        close(sock);
        return PORT_FILTERED;
    }

    /* Build a per-connection copy of the target address with the port
     * filled in (target_addr was resolved once in main.c without a port). */
    struct sockaddr_storage addr = cfg->target_addr;
    if (cfg->family == AF_INET) {
        ((struct sockaddr_in *)&addr)->sin_port = htons((uint16_t)port);
    } else {
        ((struct sockaddr_in6 *)&addr)->sin6_port = htons((uint16_t)port);
    }

    int rc = connect(sock, (struct sockaddr *)&addr, cfg->addr_len);
    if (rc == 0) {
        /* Rare on a loopback/very-low-latency target: connect() finished
         * synchronously. Still fully open. */
        *out_sock = sock;
        return PORT_OPEN;
    }

    if (errno != EINPROGRESS) {
        /* Immediate, definitive failure - e.g. ECONNREFUSED means a host
         * is up and actively rejecting the connection (closed port). */
        close(sock);
        return PORT_CLOSED;
    }

    /* Connection attempt is in flight. Wait for the socket to become
     * writable (that's the POSIX signal that connect() has resolved,
     * one way or the other) or for our timeout to elapse. */
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);

    struct timeval tv;
    tv.tv_sec  = cfg->connect_timeout_ms / 1000;
    tv.tv_usec = (cfg->connect_timeout_ms % 1000) * 1000;

    int sel = select(sock + 1, NULL, &write_fds, NULL, &tv);

    if (sel == 0) {
        /* Timed out: no response at all, most consistent with a firewall
         * silently dropping SYN packets. */
        close(sock);
        return PORT_FILTERED;
    }
    if (sel < 0) {
        /* select() itself failed (e.g. EINTR from a signal). Treat
         * conservatively as filtered/unknown rather than open. */
        close(sock);
        return PORT_FILTERED;
    }

    /* Socket is writable - check SO_ERROR to distinguish "connected
     * successfully" from "connection attempt failed asynchronously". */
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        close(sock);
        return PORT_FILTERED;
    }

    if (so_error != 0) {
        close(sock);
        return PORT_CLOSED;
    }

    /* Success. Hand back a connected socket; switch it back to blocking
     * mode with a short timeout so banner.c can use simple read()/write()
     * calls without juggling EAGAIN/EWOULDBLOCK itself. */
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    }

    struct timeval rcv_tv;
    rcv_tv.tv_sec  = cfg->read_timeout_ms / 1000;
    rcv_tv.tv_usec = (cfg->read_timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &rcv_tv, sizeof(rcv_tv));

    *out_sock = sock;
    return PORT_OPEN;
}
