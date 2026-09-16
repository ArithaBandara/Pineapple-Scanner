/*
 * main.c
 * ------
 * CLI entry point: parses arguments, resolves the target, builds the port
 * list, wires up the task queue + thread pool, waits for the scan to
 * finish, and prints a results table.
 *
 * Usage:
 *   ./portscan -H <host> [-p <ports>] [-t <threads>] [-w <timeout_s>]
 *
 *   -H host      target hostname or IP address (required)
 *   -p ports     "80" | "1-1024" | "22,80,443,8080-8090"  (default: 1-1024)
 *   -t threads   worker pool size, 1-200                  (default: 50)
 *   -w timeout   per-connection timeout in seconds, may be fractional
 *                (e.g. 0.5)                                (default: 1.0)
 *   -r timeout   banner-read timeout in seconds            (default: 1.5)
 *   -n           don't load/save/diff the per-target scan history
 *
 * NOTE: -h is reserved by getopt convention for "help", so the target
 * host flag here is capital -H to avoid colliding with a --help style
 * usage message.
 *
 * Scan history: unless -n is given, every scan is automatically compared
 * against the previous scan of the same target (if any) and then saved
 * as the new baseline, under $HOME/.portscan_history/. This is how you
 * get a "what changed since last time" report for free.
 */

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------- */
/* Port spec parsing: "80" / "1-1024" / "22,80,443,8080-8090"           */
/* ------------------------------------------------------------------- */

static int int_cmp(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

int parse_port_spec(const char *spec, int **out_ports) {
    if (!spec || !*spec) return -1;

    /* First pass: figure out an upper bound on how many ports this could
     * expand to, so we can allocate once. Worst case is every character
     * is a distinct single-port entry; ranges only ever shrink that
     * bound relative to their character count, so this is always safe. */
    size_t max_possible = 1;
    for (const char *c = spec; *c; c++) {
        if (*c == ',') max_possible++;
    }

    /* A single range like "1-65535" needs up to 65535 slots even though
     * it has no commas, so use the theoretical max port count as a floor
     * for the allocation instead of trusting comma-counting alone. */
    size_t cap = max_possible > 65535 ? max_possible : 65535;
    int *buf = malloc(cap * sizeof(int));
    if (!buf) return -1;
    size_t n = 0;

    char *copy = strdup(spec);
    if (!copy) { free(buf); return -1; }

    char *saveptr_outer = NULL;
    char *token = strtok_r(copy, ",", &saveptr_outer);
    while (token) {
        /* Trim incidental whitespace around the token. */
        while (isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token);
        while (end > token && isspace((unsigned char)*(end - 1))) *--end = '\0';

        char *dash = strchr(token, '-');
        long lo, hi;

        if (dash) {
            *dash = '\0';
            char *lo_str = token;
            char *hi_str = dash + 1;

            char *endptr = NULL;
            errno = 0;
            lo = strtol(lo_str, &endptr, 10);
            if (errno != 0 || endptr == lo_str || *endptr != '\0') { free(buf); free(copy); return -1; }

            errno = 0;
            hi = strtol(hi_str, &endptr, 10);
            if (errno != 0 || endptr == hi_str || *endptr != '\0') { free(buf); free(copy); return -1; }
        } else {
            char *endptr = NULL;
            errno = 0;
            lo = hi = strtol(token, &endptr, 10);
            if (errno != 0 || endptr == token || *endptr != '\0') { free(buf); free(copy); return -1; }
        }

        if (lo < 1 || hi > 65535 || lo > hi) { free(buf); free(copy); return -1; }

        for (long p = lo; p <= hi; p++) {
            if (n >= cap) {
                /* Should be unreachable given the cap computation above,
                 * but guard against it rather than overflow the buffer. */
                size_t new_cap = cap * 2;
                int *grown = realloc(buf, new_cap * sizeof(int));
                if (!grown) { free(buf); free(copy); return -1; }
                buf = grown;
                cap = new_cap;
            }
            buf[n++] = (int)p;
        }

        token = strtok_r(NULL, ",", &saveptr_outer);
    }
    free(copy);

    if (n == 0) { free(buf); return -1; }

    /* Sort then de-duplicate, so overlapping ranges like "20-25,22,22"
     * don't scan the same port twice. */
    qsort(buf, n, sizeof(int), int_cmp);
    size_t unique = 1;
    for (size_t i = 1; i < n; i++) {
        if (buf[i] != buf[unique - 1]) {
            buf[unique++] = buf[i];
        }
    }

    int *shrunk = realloc(buf, unique * sizeof(int));
    *out_ports = shrunk ? shrunk : buf; /* realloc-to-smaller can't fail in practice */
    return (int)unique;
}

/* ------------------------------------------------------------------- */
/* Target resolution                                                    */
/* ------------------------------------------------------------------- */

static bool resolve_target(scan_config_t *cfg) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;   /* accept IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(cfg->target_host, NULL, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "error: could not resolve host '%s': %s\n",
                cfg->target_host, gai_strerror(rc));
        return false;
    }

    /* Take the first result. Store the raw sockaddr; per-port code fills
     * in sin_port/sin6_port later. */
    memcpy(&cfg->target_addr, res->ai_addr, res->ai_addrlen);
    cfg->addr_len = (socklen_t)res->ai_addrlen;
    cfg->family   = res->ai_family;

    freeaddrinfo(res);
    return true;
}

static void print_resolved_target(const scan_config_t *cfg) {
    char ip_str[INET6_ADDRSTRLEN] = {0};
    void *addr_ptr;

    if (cfg->family == AF_INET) {
        addr_ptr = &((struct sockaddr_in *)&cfg->target_addr)->sin_addr;
    } else {
        addr_ptr = &((struct sockaddr_in6 *)&cfg->target_addr)->sin6_addr;
    }
    inet_ntop(cfg->family, addr_ptr, ip_str, sizeof(ip_str));

    if (strcmp(cfg->target_host, ip_str) == 0) {
        printf("Target      : %s\n", ip_str);
    } else {
        printf("Target      : %s (%s)\n", cfg->target_host, ip_str);
    }
}

/* ------------------------------------------------------------------- */
/* CLI                                                                   */
/* ------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -H <host> [-p <ports>] [-t <threads>] [-w <timeout_s>] [-r <read_timeout_s>]\n"
        "\n"
        "  -H host       target hostname or IP address (required)\n"
        "  -p ports      \"80\" | \"1-1024\" | \"22,80,443,8080-8090\"  (default: 1-1024)\n"
        "  -t threads    worker pool size, 1-%d                        (default: %d)\n"
        "  -w timeout    per-connection timeout in seconds, e.g. 0.5     (default: 1.0)\n"
        "  -r timeout    banner-read timeout in seconds                 (default: 1.5)\n"
        "  -n            skip scan history: no load, no diff, no save\n"
        "\n"
        "Every scan is automatically diffed against the previous scan of the same\n"
        "target (if any) and saved as the new baseline under $HOME/.portscan_history/.\n"
        "Pass -n to opt out.\n"
        "\n"
        "Only scan hosts and networks you own or are explicitly authorized to test.\n",
        prog, MAX_THREADS, DEFAULT_THREADS);
}

static double parse_seconds_arg(const char *s, bool *ok) {
    char *endptr = NULL;
    errno = 0;
    double v = strtod(s, &endptr);
    *ok = (errno == 0 && endptr != s && *endptr == '\0' && v >= 0.0);
    return v;
}

static void parse_args(int argc, char **argv, scan_config_t *cfg) {
    /* Defaults */
    memset(cfg, 0, sizeof(*cfg));
    cfg->thread_count       = DEFAULT_THREADS;
    cfg->connect_timeout_ms = DEFAULT_TIMEOUT_MS;
    cfg->read_timeout_ms    = 1500;

    const char *port_spec = "1-1024";
    bool have_host = false;

    int opt;
    while ((opt = getopt(argc, argv, "H:p:t:w:r:nh")) != -1) {
        switch (opt) {
            case 'H':
                strncpy(cfg->target_host, optarg, MAX_HOST_LEN - 1);
                cfg->target_host[MAX_HOST_LEN - 1] = '\0';
                have_host = true;
                break;
            case 'p':
                port_spec = optarg;
                break;
            case 't': {
                char *endptr = NULL;
                errno = 0;
                long t = strtol(optarg, &endptr, 10);
                if (errno != 0 || endptr == optarg || *endptr != '\0' || t < 1 || t > MAX_THREADS) {
                    fprintf(stderr, "error: -t must be an integer between 1 and %d\n", MAX_THREADS);
                    exit(EXIT_FAILURE);
                }
                cfg->thread_count = (int)t;
                break;
            }
            case 'w': {
                bool ok;
                double secs = parse_seconds_arg(optarg, &ok);
                if (!ok || secs <= 0.0) {
                    fprintf(stderr, "error: -w must be a positive number of seconds\n");
                    exit(EXIT_FAILURE);
                }
                cfg->connect_timeout_ms = (int)(secs * 1000.0);
                break;
            }
            case 'r': {
                bool ok;
                double secs = parse_seconds_arg(optarg, &ok);
                if (!ok || secs <= 0.0) {
                    fprintf(stderr, "error: -r must be a positive number of seconds\n");
                    exit(EXIT_FAILURE);
                }
                cfg->read_timeout_ms = (int)(secs * 1000.0);
                break;
            }
            case 'n':
                cfg->no_history = true;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                exit(opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    if (!have_host) {
        fprintf(stderr, "error: -H <host> is required\n\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    cfg->port_count = parse_port_spec(port_spec, &cfg->ports);
    if (cfg->port_count <= 0) {
        fprintf(stderr, "error: invalid port specification '%s'\n", port_spec);
        exit(EXIT_FAILURE);
    }
}

/* ------------------------------------------------------------------- */
/* Results table                                                        */
/* ------------------------------------------------------------------- */

static int result_cmp(const void *a, const void *b) {
    return ((const scan_result_t *)a)->port - ((const scan_result_t *)b)->port;
}

static void print_results(result_store_t *rs) {
    if (rs->count > 0) {
        qsort(rs->items, (size_t)rs->count, sizeof(scan_result_t), result_cmp);
    }

    printf("\n%-8s %-8s %s\n", "PORT", "STATE", "BANNER");
    printf("%-8s %-8s %s\n", "----", "-----", "------");

    if (rs->count == 0) {
        printf("(no open ports found)\n");
        return;
    }

    for (int i = 0; i < rs->count; i++) {
        printf("%-8d %-8s %s\n",
               rs->items[i].port,
               "open",
               rs->items[i].banner[0] ? rs->items[i].banner : "(no banner)");
    }
}

/* ------------------------------------------------------------------- */
/* main                                                                  */
/* ------------------------------------------------------------------- */

int main(int argc, char **argv) {
    scan_config_t cfg;
    parse_args(argc, argv, &cfg);

    if (!resolve_target(&cfg)) {
        free(cfg.ports);
        return EXIT_FAILURE;
    }

    printf("=== Multi-threaded TCP Port Scanner ===\n");
    print_resolved_target(&cfg);
    printf("Ports       : %d\n", cfg.port_count);
    printf("Threads     : %d\n", cfg.thread_count);
    printf("Timeouts    : connect=%dms read=%dms\n", cfg.connect_timeout_ms, cfg.read_timeout_ms);
    printf("Note        : only scan systems you own or are authorized to test.\n\n");

    task_queue_t queue;
    task_queue_init(&queue, cfg.port_count);

    result_store_t results;
    result_store_init(&results, 16);

    for (int i = 0; i < cfg.port_count; i++) {
        scan_task_t task = { .port = cfg.ports[i] };
        task_queue_push(&queue, task);
    }
    /* All work is enqueued up front, so it's safe to signal shutdown
     * immediately; task_queue_pop() still drains every already-queued
     * item before any worker sees "no more work". */
    task_queue_shutdown(&queue);

    /* Never spin up more workers than there is work to do. */
    if (cfg.thread_count > cfg.port_count) {
        cfg.thread_count = cfg.port_count;
    }

    thread_pool_t *pool = thread_pool_create(&cfg, &queue, &results, cfg.port_count);
    thread_pool_join(pool);

    print_results(&results); /* sorts results.items by port as a side effect */

    printf("\nScan complete: %d/%d ports open.\n", results.count, cfg.port_count);

    if (!cfg.no_history) {
        scan_result_t *prev_items = NULL;
        int prev_count = 0;
        time_t prev_when = 0;

        bool have_baseline = history_load_previous(&cfg, &prev_items, &prev_count, &prev_when);
        if (have_baseline) {
            history_print_diff(prev_items, prev_count, prev_when, results.items, results.count);
        } else {
            printf("\n(No previous scan on record for this target - saving this run as the baseline.)\n");
        }

        history_save_current(&cfg, results.items, results.count);
        free(prev_items);
    }

    thread_pool_destroy(pool);
    result_store_destroy(&results);
    task_queue_destroy(&queue);
    free(cfg.ports);

    return EXIT_SUCCESS;
}
