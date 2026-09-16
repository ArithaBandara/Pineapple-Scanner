/*
 * scanner.h
 * ---------
 * Shared type definitions and function prototypes for the multi-threaded
 * TCP port scanner / banner grabber.
 *
 * Design summary
 * --------------
 *   main.c        -> parses CLI args, resolves the target, builds the list
 *                     of ports to scan, wires up the queue + thread pool,
 *                     waits for completion, prints the results table.
 *   threadpool.c  -> a fixed-size pool of worker threads pulling jobs from
 *                     a mutex/condvar-protected FIFO queue (producer once,
 *                     many consumers).
 *   network.c     -> non-blocking connect() + select()-based timeout logic
 *                     ("is this port open?").
 *   banner.c      -> once a socket is open, send a protocol-appropriate
 *                     probe and read back a greeting/response with its own
 *                     short read timeout.
 *
 * IMPORTANT: This tool performs active TCP connection attempts against a
 * target host. Only ever point it at hosts/networks you own or have
 * explicit written authorization to test. Unauthorized scanning of systems
 * you do not control may be illegal in your jurisdiction.
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <pthread.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define MAX_BANNER_LEN      256
#define DEFAULT_THREADS     50
#define MAX_THREADS         200
#define DEFAULT_TIMEOUT_MS  1000
#define MAX_HOST_LEN        256

/* ------------------------------------------------------------------- */
/* Global configuration parsed from the command line                    */
/* ------------------------------------------------------------------- */
typedef struct {
    char target_host[MAX_HOST_LEN];   /* hostname or IP literal, as typed */
    struct sockaddr_storage target_addr; /* resolved address, ready to use */
    socklen_t addr_len;
    int  family;                      /* AF_INET or AF_INET6              */

    int *ports;                       /* heap array of ports to scan      */
    int  port_count;

    int  thread_count;                /* worker pool size                 */
    int  connect_timeout_ms;          /* connect() timeout, milliseconds  */
    int  read_timeout_ms;             /* banner-read timeout, milliseconds*/

    bool no_history;                  /* -n: skip baseline load/save/diff */
} scan_config_t;

/* ------------------------------------------------------------------- */
/* One unit of work: "probe this port"                                  */
/* ------------------------------------------------------------------- */
typedef struct {
    int port;
} scan_task_t;

/* ------------------------------------------------------------------- */
/* Thread-safe bounded FIFO queue of scan_task_t                        */
/* ------------------------------------------------------------------- */
typedef struct {
    scan_task_t     *tasks;
    int              capacity;
    int              head;      /* index of next item to pop  */
    int              tail;      /* index of next free slot    */
    int              count;     /* items currently queued     */
    bool             shutting_down;
    pthread_mutex_t  lock;
    pthread_cond_t   not_empty;
} task_queue_t;

void task_queue_init(task_queue_t *q, int capacity);
void task_queue_destroy(task_queue_t *q);
void task_queue_push(task_queue_t *q, scan_task_t task);
bool task_queue_pop(task_queue_t *q, scan_task_t *out); /* false => drained+shutdown */
void task_queue_shutdown(task_queue_t *q);

/* ------------------------------------------------------------------- */
/* Result of probing a single port                                      */
/* ------------------------------------------------------------------- */
typedef enum {
    PORT_CLOSED = 0,
    PORT_OPEN,
    PORT_FILTERED   /* timed out / no response either way */
} port_state_t;

typedef struct {
    int          port;
    port_state_t state;
    char         banner[MAX_BANNER_LEN];
} scan_result_t;

/* Thread-safe growable array collecting results (open ports + banners) */
typedef struct {
    scan_result_t   *items;
    int              capacity;
    int              count;
    pthread_mutex_t  lock;
} result_store_t;

void result_store_init(result_store_t *rs, int initial_capacity);
void result_store_destroy(result_store_t *rs);
void result_store_add(result_store_t *rs, scan_result_t r);

/* ------------------------------------------------------------------- */
/* Thread pool                                                          */
/* ------------------------------------------------------------------- */
typedef struct {
    pthread_t             *workers;
    int                     worker_count;
    task_queue_t           *queue;
    result_store_t         *results;
    const scan_config_t    *config;

    /* live progress, protected by progress_lock */
    pthread_mutex_t         progress_lock;
    int                     completed;
    int                     total;
} thread_pool_t;

thread_pool_t *thread_pool_create(const scan_config_t *cfg,
                                   task_queue_t *queue,
                                   result_store_t *results,
                                   int total_tasks);
void thread_pool_join(thread_pool_t *pool);     /* blocks until all workers exit */
void thread_pool_destroy(thread_pool_t *pool);  /* frees the pool struct itself  */

/* ------------------------------------------------------------------- */
/* network.c                                                            */
/* ------------------------------------------------------------------- */
/*
 * Attempt a non-blocking TCP connect to cfg->target_addr on `port`,
 * waiting up to cfg->connect_timeout_ms via select().
 *
 * On success (PORT_OPEN) *out_sock holds an open, connected, blocking
 * socket the caller owns and must close(). On any other result *out_sock
 * is -1 and no descriptor is leaked.
 */
port_state_t probe_port(const scan_config_t *cfg, int port, int *out_sock);

/* ------------------------------------------------------------------- */
/* banner.c                                                             */
/* ------------------------------------------------------------------- */
/*
 * Given an already-connected socket for `port`, send a protocol-aware
 * probe if one is known for that port (HTTP HEAD, SMTP, etc.) or simply
 * wait for a passive greeting (SSH/FTP/SMTP servers), then read back up
 * to out_len-1 bytes within cfg->read_timeout_ms. Result is a
 * NUL-terminated, single-line, printable string in `out`.
 */
void grab_banner(const scan_config_t *cfg, int sock, int port,
                  char *out, size_t out_len);

/* ------------------------------------------------------------------- */
/* history.c                                                            */
/* ------------------------------------------------------------------- */
/*
 * Feature nmap doesn't ship with: every scan is automatically compared
 * against, then saved as, a per-target baseline on disk - so config
 * drift ("port 5900 wasn't open yesterday") is visible immediately with
 * no separate diffing tool and nothing extra for the user to remember to
 * save. Baselines live under $HOME/.portscan_history/<target>.tsv.
 */

/*
 * Loads the previous baseline for cfg->target_host, if one exists.
 * On success (a readable, well-formed baseline was found) returns true,
 * *out_items is a malloc'd array the caller must free(), *out_count is
 * its length, and *out_when is when that scan was taken. If there is no
 * prior baseline (or it's unreadable/corrupt), returns false and leaves
 * the out-params zeroed/NULL - this is a normal, expected first-run
 * condition, not an error to be reported loudly.
 */
bool history_load_previous(const scan_config_t *cfg, scan_result_t **out_items,
                            int *out_count, time_t *out_when);

/* Overwrites the on-disk baseline for cfg->target_host with the current
 * result set (open ports + banners), so the *next* run has something to
 * diff against. Writes to a temp file and rename()s it into place so a
 * crash mid-write can never corrupt the existing baseline. */
void history_save_current(const scan_config_t *cfg, const scan_result_t *items, int count);

/*
 * Prints a human-readable diff of `curr` against `prev`. Both arrays must
 * already be sorted ascending by port. Reports newly-open ports, ports
 * that closed since the baseline, ports whose banner text changed
 * (e.g. a service was upgraded/downgraded), and a summary count.
 */
void history_print_diff(const scan_result_t *prev, int prev_count, time_t prev_when,
                         const scan_result_t *curr, int curr_count);

/* ------------------------------------------------------------------- */
/* main.c helper, exposed so it can be unit-tested independently        */
/* ------------------------------------------------------------------- */
/*
 * Parses a port specification like "80" / "1-1024" / "22,80,443,8080-8090"
 * into a freshly malloc'd, de-duplicated, ascending array of ports.
 * Returns the number of ports on success, -1 on a malformed spec.
 */
int parse_port_spec(const char *spec, int **out_ports);

#endif /* SCANNER_H */
