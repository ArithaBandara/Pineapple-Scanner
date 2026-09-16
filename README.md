<div align="center">

<img src="img/pineappple.png" width="256" alt="Pineapple-Scanner Logo">
<h1>Pineapple-Scanner (C11)</h1>

</div>

A production-style, from-scratch TCP port scanner: a fixed-size POSIX
thread pool pulls ports off a mutex/condvar-protected queue, probes each
one with a non-blocking `connect()` bounded by `select()`, grabs a
service banner on anything open, and — a feature stock `nmap` doesn't
give you — automatically diffs every scan against the previous scan of
the same target.

> **Only scan hosts and networks you own or have explicit written
> authorization to test.** Unauthorized port scanning of systems you do
> not control may be illegal in your jurisdiction. This tool is intended
> for your own infrastructure, lab environments, and authorized
> penetration tests / security assessments.

## File structure

```
c_port_scanner/
├── include/
│   └── scanner.h       # Structs, thread pool defs, function prototypes
├── src/
│   ├── main.c          # CLI parsing, port-spec parsing, driver, reporting
│   ├── threadpool.c    # Mutex/condvar queue + worker thread lifecycle
│   ├── network.c       # Non-blocking connect() + select() timeout logic
│   ├── banner.c        # Protocol-aware banner probing/sanitizing
│   └── history.c       # Per-target scan baselines + change detection
├── Makefile            # -O3 -pthread -Wall -Wextra -Wpedantic, + debug target
└── README.md
```

## Compiling

Requires a POSIX system (Linux/macOS/BSD) with a C11 compiler and pthreads.

```bash
cd c_port_scanner
make            # builds ./portscan  (-O3, no warnings under -Wall -Wextra -Wpedantic)
```

A sanitizer-instrumented debug build is also available for development:

```bash
make debug      # builds ./portscan-debug with -fsanitize=address,undefined -g -O0
```

`make clean` removes all build artifacts.

## Running it safely on a local test target

Never point this at a host you don't control. To try it out safely,
stand up something to scan on **localhost** first:

```bash
# Terminal 1: a harmless target service
python3 -m http.server 8080 --bind 127.0.0.1

# Terminal 2: scan only localhost, only a handful of ports
./portscan -H 127.0.0.1 -p 20-25,80,8080,8443 -t 20 -w 0.5
```

You should see a live progress bar, then a results table showing port
`8080` open with an HTTP banner. From there you can widen `-p` (e.g.
`-p 1-1024`) against hosts you own once you're comfortable with the
tool's behavior and timing.

## CLI options

```
./portscan -H <host> [-p <ports>] [-t <threads>] [-w <timeout_s>] [-r <read_timeout_s>] [-n]

  -H host       target hostname or IP address (required)
  -p ports      "80" | "1-1024" | "22,80,443,8080-8090"   (default: 1-1024)
  -t threads    worker pool size, 1-200                    (default: 50)
  -w timeout    per-connection timeout in seconds, e.g. 0.5 (default: 1.0)
  -r timeout    banner-read timeout in seconds              (default: 1.5)
  -n            skip scan history: no load, no diff, no save
```

(`-h` prints usage; the target flag is capital `-H` so it doesn't collide
with the conventional `-h`-for-help.)

## The feature nmap doesn't have: automatic scan-history diffing

Unless you pass `-n`, every scan is:

1. **Compared** against the previous scan of the same target (if one
   exists) — reporting newly opened ports, ports that have since closed,
   and ports whose banner text changed (e.g. a service got
   upgraded/downgraded).
2. **Saved** as the new baseline for next time.

`nmap` itself has no built-in equivalent — comparing two scans requires
manually saving XML reports (`-oX`) from two separate runs and feeding
them to its separate `ndiff` utility. Here it's automatic and stateful:
just run the scanner again later and the diff appears for free.

Baselines are stored one-per-target as small, human-readable TSV files
under `$HOME/.portscan_history/<target>.tsv`:

```
# scanned_at=1789535636 target=127.0.0.1
8080    HTTP/1.0 200 OK Server: SimpleHTTP/0.6 Python/3.12.3 ...
```

Example second-run output after a service moved from port 8000 to 9999:

```
=== Change Detection (baseline: 3.2h ago) ===
  - closed   8000   (was: HTTP/1.0 200 OK Server: SimpleHTTP/0.6 ...)
  + new      9999   (no banner)
  summary: 1 new, 1 closed, 0 changed, 0 unchanged
```

Writes are done via a temp file + `rename()` (atomic on POSIX
filesystems), so a crash mid-scan can never corrupt an existing
baseline.

## Concurrency design

- **One producer, many consumers.** `main()` resolves the target, builds
  the full port list, pushes every port onto `task_queue_t` up front,
  then immediately calls `task_queue_shutdown()`. This does *not* stop
  workers from processing what's already queued — `task_queue_pop()` is
  written as "drain, then stop": it keeps handing out items while
  `count > 0`, and only reports "no more work" once the queue is both
  empty *and* shutting down. That guarantees every port is scanned
  exactly once even though all tasks are enqueued before any worker
  might see the shutdown flag.
- **Condition variable, not busy-waiting.** Workers blocked on an empty,
  not-yet-shutdown queue sleep on `pthread_cond_wait`, and
  `task_queue_push`/`task_queue_shutdown` wake them via
  `pthread_cond_signal`/`pthread_cond_broadcast`. No thread ever spins.
- **Bounded, pre-sized queue.** The queue is allocated with exactly
  `port_count` slots since every task is known and enqueued up front —
  no dynamic growth needed in the hot path.
- **Thread-safe result collection.** Each worker only touches shared
  state through `result_store_add()` (mutex-protected, grows via
  `realloc` when needed) and a small `progress_lock`-guarded counter used
  to redraw the ANSI progress bar in place (`\r` + `\033[K`).

## Socket / timeout mechanics

- **Why non-blocking + `select()`?** A plain blocking `connect()` against
  a *filtered* port (one whose firewall silently drops the SYN) can hang
  for the OS's full TCP timeout — commonly 30–120+ seconds. That would
  stall an entire worker thread on a single dead port. Setting the
  socket non-blocking makes `connect()` return immediately with
  `EINPROGRESS`, and `select()` on the socket's write-set lets the
  scanner enforce its own short deadline (`-w`) while still waking up the
  instant the OS actually resolves the connection.
- **Distinguishing open / closed / filtered after `select()` wakes up:**
  the socket becoming writable only means the *attempt* resolved one way
  or another — `getsockopt(SO_ERROR)` is what tells you whether it
  resolved to success or to a specific error (e.g. `ECONNREFUSED` for
  "closed"). A `select()` timeout with no wake-up at all is classified as
  *filtered* (most consistent with a firewall dropping packets rather
  than a host actively rejecting the connection).
- **Banner grabbing reuses the same connected socket.** Once open, the
  socket is switched back to blocking mode with `SO_RCVTIMEO`/
  `SO_SNDTIMEO` set from `-r`, so `banner.c` can use plain `read()`/
  `write()` without re-implementing timeout logic — a timed-out read
  simply returns an error, which is treated as "open, but no banner".
- **Protocol awareness:** ports where the *server* speaks first (SSH,
  FTP, SMTP-style greetings) are handled by just reading immediately;
  ports where the *client* must speak first (80/8080/8000/443) get a
  minimal `HEAD / HTTP/1.0` probe before the read.

## Memory safety

Verified with an AddressSanitizer + UndefinedBehaviorSanitizer build
(`make debug`) run against a live local target across a multi-hundred
port scan: zero leaks, zero sanitizer errors. Every socket is `close()`d
by exactly one owner (the worker that opened it), every `malloc`/
`calloc`/`realloc` has a matching `free()` on all exit paths, and the
`scan_config_t.ports` array, thread pool, task queue, and result store
are each torn down once in `main()` after `thread_pool_join()` returns.

If you have `valgrind` available, the release build is equally
Valgrind-clean:

```bash
make
valgrind --leak-check=full ./portscan -H 127.0.0.1 -p 1-100
```
=======
# Pineapple-Scanner
A security scanning tool that discovers services, correlates them with known vulnerabilities, maintains scan history, and detects changes between scans.
