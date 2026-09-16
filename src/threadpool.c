/*
 * threadpool.c
 * ------------
 * A classic bounded producer/consumer queue guarded by a mutex + condition
 * variable, plus the fixed-size worker pool that drains it.
 *
 * Concurrency notes:
 *   - Exactly one producer (main thread) fills the queue up front, then
 *     calls task_queue_shutdown(). Many consumer threads (workers) call
 *     task_queue_pop() in a loop.
 *   - The mutex protects head/tail/count/shutting_down. The condition
 *     variable `not_empty` lets pop() sleep (instead of busy-spinning)
 *     while the queue is empty but not yet shut down.
 *   - Shutdown is "drain, then stop": once shutting_down is set, pop()
 *     still hands out any items already queued; it only returns false
 *     once the queue is BOTH empty AND shutting down. This guarantees
 *     every pushed task gets processed exactly once, even though all
 *     tasks are pushed before shutdown is signalled.
 */

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------- */
/* Task queue                                                           */
/* ------------------------------------------------------------------- */

void task_queue_init(task_queue_t *q, int capacity) {
    q->tasks = calloc((size_t)capacity, sizeof(scan_task_t));
    if (!q->tasks) {
        fprintf(stderr, "fatal: out of memory allocating task queue (%d slots)\n", capacity);
        exit(EXIT_FAILURE);
    }
    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->shutting_down = false;

    if (pthread_mutex_init(&q->lock, NULL) != 0 ||
        pthread_cond_init(&q->not_empty, NULL) != 0) {
        fprintf(stderr, "fatal: failed to initialize queue synchronization primitives\n");
        exit(EXIT_FAILURE);
    }
}

void task_queue_destroy(task_queue_t *q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    free(q->tasks);
    q->tasks = NULL;
}

void task_queue_push(task_queue_t *q, scan_task_t task) {
    pthread_mutex_lock(&q->lock);

    /* All tasks are enqueued once, up front, sized exactly to port_count,
     * so the queue never actually fills; this guard just keeps the code
     * defensively correct if that assumption ever changes. */
    if (q->count == q->capacity) {
        fprintf(stderr, "fatal: task queue overflow (capacity=%d)\n", q->capacity);
        pthread_mutex_unlock(&q->lock);
        exit(EXIT_FAILURE);
    }

    q->tasks[q->tail] = task;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

bool task_queue_pop(task_queue_t *q, scan_task_t *out) {
    pthread_mutex_lock(&q->lock);

    while (q->count == 0 && !q->shutting_down) {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }

    if (q->count == 0) {
        /* Empty AND shutting down: nothing left to do, ever. */
        pthread_mutex_unlock(&q->lock);
        return false;
    }

    *out = q->tasks[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;

    pthread_mutex_unlock(&q->lock);
    return true;
}

void task_queue_shutdown(task_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    q->shutting_down = true;
    pthread_cond_broadcast(&q->not_empty); /* wake every sleeping worker */
    pthread_mutex_unlock(&q->lock);
}

/* ------------------------------------------------------------------- */
/* Result store                                                         */
/* ------------------------------------------------------------------- */

void result_store_init(result_store_t *rs, int initial_capacity) {
    if (initial_capacity < 1) initial_capacity = 1;
    rs->items = calloc((size_t)initial_capacity, sizeof(scan_result_t));
    if (!rs->items) {
        fprintf(stderr, "fatal: out of memory allocating result store\n");
        exit(EXIT_FAILURE);
    }
    rs->capacity = initial_capacity;
    rs->count = 0;
    if (pthread_mutex_init(&rs->lock, NULL) != 0) {
        fprintf(stderr, "fatal: failed to initialize result store mutex\n");
        exit(EXIT_FAILURE);
    }
}

void result_store_destroy(result_store_t *rs) {
    pthread_mutex_destroy(&rs->lock);
    free(rs->items);
    rs->items = NULL;
}

void result_store_add(result_store_t *rs, scan_result_t r) {
    pthread_mutex_lock(&rs->lock);

    if (rs->count == rs->capacity) {
        int new_cap = rs->capacity * 2;
        scan_result_t *grown = realloc(rs->items, (size_t)new_cap * sizeof(scan_result_t));
        if (!grown) {
            fprintf(stderr, "fatal: out of memory growing result store\n");
            pthread_mutex_unlock(&rs->lock);
            exit(EXIT_FAILURE);
        }
        rs->items = grown;
        rs->capacity = new_cap;
    }

    rs->items[rs->count++] = r;
    pthread_mutex_unlock(&rs->lock);
}

/* ------------------------------------------------------------------- */
/* Worker thread body                                                   */
/* ------------------------------------------------------------------- */

/* Passed to each worker thread; keeps pthread_create's single void* arg
 * bundle small and explicit rather than reaching through globals. */
typedef struct {
    thread_pool_t *pool;
} worker_arg_t;

static void print_progress_locked(thread_pool_t *pool) {
    /* Caller holds pool->progress_lock. Draws a simple in-place progress
     * bar using ANSI escape codes: \r returns the cursor to column 0 and
     * \033[K clears to end of line, so each update overwrites the last
     * instead of scrolling the terminal. */
    int done = pool->completed;
    int total = pool->total;
    int pct = total > 0 ? (done * 100) / total : 100;

    const int bar_width = 30;
    int filled = (pct * bar_width) / 100;

    fprintf(stderr, "\r\033[K[");
    for (int i = 0; i < bar_width; i++) {
        fputc(i < filled ? '#' : '-', stderr);
    }
    fprintf(stderr, "] %3d%%  (%d/%d ports)", pct, done, total);
    fflush(stderr);
}

static void *worker_main(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    thread_pool_t *pool = wa->pool;
    const scan_config_t *cfg = pool->config;

    scan_task_t task;
    while (task_queue_pop(pool->queue, &task)) {
        int sock = -1;
        port_state_t state = probe_port(cfg, task.port, &sock);

        if (state == PORT_OPEN) {
            scan_result_t result;
            memset(&result, 0, sizeof(result));
            result.port = task.port;
            result.state = PORT_OPEN;
            grab_banner(cfg, sock, task.port, result.banner, sizeof(result.banner));
            close(sock); /* each worker owns and closes its own socket */
            result_store_add(pool->results, result);
        }
        /* PORT_CLOSED / PORT_FILTERED: nothing to record, matches nmap-style
         * "only report what's actually reachable" default behavior. */

        pthread_mutex_lock(&pool->progress_lock);
        pool->completed++;
        print_progress_locked(pool);
        pthread_mutex_unlock(&pool->progress_lock);
    }

    free(wa);
    return NULL;
}

/* ------------------------------------------------------------------- */
/* Pool lifecycle                                                       */
/* ------------------------------------------------------------------- */

thread_pool_t *thread_pool_create(const scan_config_t *cfg,
                                   task_queue_t *queue,
                                   result_store_t *results,
                                   int total_tasks) {
    thread_pool_t *pool = calloc(1, sizeof(thread_pool_t));
    if (!pool) {
        fprintf(stderr, "fatal: out of memory allocating thread pool\n");
        exit(EXIT_FAILURE);
    }

    pool->worker_count = cfg->thread_count;
    pool->workers = calloc((size_t)pool->worker_count, sizeof(pthread_t));
    if (!pool->workers) {
        fprintf(stderr, "fatal: out of memory allocating worker handles\n");
        free(pool);
        exit(EXIT_FAILURE);
    }

    pool->queue = queue;
    pool->results = results;
    pool->config = cfg;
    pool->completed = 0;
    pool->total = total_tasks;

    if (pthread_mutex_init(&pool->progress_lock, NULL) != 0) {
        fprintf(stderr, "fatal: failed to initialize progress mutex\n");
        free(pool->workers);
        free(pool);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < pool->worker_count; i++) {
        worker_arg_t *wa = malloc(sizeof(worker_arg_t));
        if (!wa) {
            fprintf(stderr, "fatal: out of memory allocating worker argument\n");
            exit(EXIT_FAILURE);
        }
        wa->pool = pool;

        int rc = pthread_create(&pool->workers[i], NULL, worker_main, wa);
        if (rc != 0) {
            fprintf(stderr, "fatal: pthread_create failed for worker %d (errno=%d)\n", i, rc);
            free(wa);
            /* Shut the queue down so already-started workers can exit
             * cleanly, then bail out rather than limping along
             * under-resourced. */
            task_queue_shutdown(queue);
            pool->worker_count = i; /* only join the ones actually created */
            thread_pool_join(pool);
            exit(EXIT_FAILURE);
        }
    }

    return pool;
}

void thread_pool_join(thread_pool_t *pool) {
    for (int i = 0; i < pool->worker_count; i++) {
        pthread_join(pool->workers[i], NULL);
    }
    /* Final newline so the shell prompt doesn't land on top of the
     * in-place progress bar. */
    fprintf(stderr, "\n");
}

void thread_pool_destroy(thread_pool_t *pool) {
    pthread_mutex_destroy(&pool->progress_lock);
    free(pool->workers);
    free(pool);
}
