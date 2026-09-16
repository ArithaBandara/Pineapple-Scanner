/*
 * history.c
 * ---------
 * Persistent per-target scan baselines, plus diffing the current scan
 * against the previous one.
 *
 * This is the one feature stock `nmap` does not give you for free: nmap
 * will happily rescan a host, but to see *what changed* since last time
 * you'd normally save two XML reports (-oX) and run its separate `ndiff`
 * companion tool against them yourself. Here it's automatic - every scan
 * doubles as the baseline for the next one, so newly-opened ports,
 * closed ports, and banner/version changes ("nginx 1.24 -> 1.26") show up
 * immediately with zero extra steps and nothing to remember to save.
 *
 * Storage format: one small, human-readable, greppable text file per
 * target at
 *
 *     $HOME/.portscan_history/<sanitized-target>.tsv
 *
 * ("$TMPDIR"-equivalent /tmp if $HOME isn't set), a header line recording
 * when the scan ran, followed by one "<port>\t<banner>" row per open
 * port. Writes go to a temp file and are rename()'d into place, which is
 * atomic on POSIX filesystems, so a crash mid-write can never corrupt an
 * existing baseline.
 */

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#define HISTORY_DIRNAME ".portscan_history"
#define HISTORY_PATH_LEN 1024

/* ------------------------------------------------------------------- */
/* Path helpers                                                         */
/* ------------------------------------------------------------------- */

static bool ensure_history_dir(char *out_dir, size_t out_dir_len) {
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/tmp";

    int n = snprintf(out_dir, out_dir_len, "%s/%s", home, HISTORY_DIRNAME);
    if (n < 0 || (size_t)n >= out_dir_len) return false;

    if (mkdir(out_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "warning: could not create history directory '%s': %s\n",
                out_dir, strerror(errno));
        return false;
    }
    return true;
}

/* Keeps alphanumerics, '.', and '-'; everything else (including ':' from
 * IPv6 literals) becomes '_'. Doesn't need to be reversible, just stable
 * and filesystem-safe. */
static void sanitize_filename(const char *in, char *out, size_t out_len) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        out[j++] = (isalnum(c) || c == '.' || c == '-') ? (char)c : '_';
    }
    out[j] = '\0';
    if (j == 0) snprintf(out, out_len, "target");
}

static bool build_history_path(const scan_config_t *cfg, char *out_path, size_t out_len) {
    char dir[HISTORY_PATH_LEN];
    if (!ensure_history_dir(dir, sizeof(dir))) return false;

    char safe_name[256];
    sanitize_filename(cfg->target_host, safe_name, sizeof(safe_name));

    int n = snprintf(out_path, out_len, "%s/%s.tsv", dir, safe_name);
    return n > 0 && (size_t)n < out_len;
}

static int result_port_cmp(const void *a, const void *b) {
    return ((const scan_result_t *)a)->port - ((const scan_result_t *)b)->port;
}

/* ------------------------------------------------------------------- */
/* Load                                                                 */
/* ------------------------------------------------------------------- */

bool history_load_previous(const scan_config_t *cfg, scan_result_t **out_items,
                            int *out_count, time_t *out_when) {
    *out_items = NULL;
    *out_count = 0;
    *out_when = 0;

    char path[HISTORY_PATH_LEN];
    if (!build_history_path(cfg, path, sizeof(path))) return false;

    FILE *f = fopen(path, "r");
    if (!f) return false; /* no baseline yet - a normal first-run state */

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return false; }

    long long epoch = 0;
    if (sscanf(line, "# scanned_at=%lld", &epoch) != 1) {
        /* Doesn't look like our file; treat as "no usable baseline"
         * rather than crashing on a foreign/corrupt file. */
        fclose(f);
        return false;
    }
    *out_when = (time_t)epoch;

    int capacity = 16, count = 0;
    scan_result_t *items = calloc((size_t)capacity, sizeof(scan_result_t));
    if (!items) { fclose(f); return false; }

    while (fgets(line, sizeof(line), f)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue; /* skip malformed row rather than aborting */
        *tab = '\0';

        char *endptr = NULL;
        errno = 0;
        long p = strtol(line, &endptr, 10);
        if (errno != 0 || endptr == line || p < 1 || p > 65535) continue;

        char *banner_start = tab + 1;
        size_t blen = strlen(banner_start);
        while (blen > 0 && (banner_start[blen - 1] == '\n' || banner_start[blen - 1] == '\r')) {
            banner_start[--blen] = '\0';
        }

        if (count == capacity) {
            int new_cap = capacity * 2;
            scan_result_t *grown = realloc(items, (size_t)new_cap * sizeof(scan_result_t));
            if (!grown) break; /* keep what we successfully parsed so far */
            items = grown;
            capacity = new_cap;
        }

        memset(&items[count], 0, sizeof(items[count]));
        items[count].port = (int)p;
        items[count].state = PORT_OPEN;
        strncpy(items[count].banner, banner_start, sizeof(items[count].banner) - 1);
        count++;
    }
    fclose(f);

    if (count > 1) {
        qsort(items, (size_t)count, sizeof(scan_result_t), result_port_cmp);
    }

    *out_items = items;
    *out_count = count;
    return true;
}

/* ------------------------------------------------------------------- */
/* Save                                                                 */
/* ------------------------------------------------------------------- */

void history_save_current(const scan_config_t *cfg, const scan_result_t *items, int count) {
    char path[HISTORY_PATH_LEN];
    if (!build_history_path(cfg, path, sizeof(path))) return;

    char tmp_path[HISTORY_PATH_LEN];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n < 0 || (size_t)n >= (int)sizeof(tmp_path)) return;

    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        fprintf(stderr, "warning: could not write scan history to '%s': %s\n",
                tmp_path, strerror(errno));
        return;
    }

    fprintf(f, "# scanned_at=%lld target=%s\n", (long long)time(NULL), cfg->target_host);
    for (int i = 0; i < count; i++) {
        /* banner.c already collapses banners to a single printable,
         * tab-free line, so a raw TSV row is safe here. */
        fprintf(f, "%d\t%s\n", items[i].port, items[i].banner);
    }

    if (fclose(f) != 0 || rename(tmp_path, path) != 0) {
        fprintf(stderr, "warning: could not finalize scan history at '%s': %s\n",
                path, strerror(errno));
        remove(tmp_path);
    }
}

/* ------------------------------------------------------------------- */
/* Diff                                                                 */
/* ------------------------------------------------------------------- */

static void format_relative_time(time_t when, char *out, size_t out_len) {
    double diff = difftime(time(NULL), when);
    if (diff < 0) diff = 0;

    if (diff < 60) {
        snprintf(out, out_len, "%.0fs ago", diff);
    } else if (diff < 3600) {
        snprintf(out, out_len, "%.0fm ago", diff / 60);
    } else if (diff < 86400) {
        snprintf(out, out_len, "%.1fh ago", diff / 3600);
    } else {
        snprintf(out, out_len, "%.1fd ago", diff / 86400);
    }
}

void history_print_diff(const scan_result_t *prev, int prev_count, time_t prev_when,
                         const scan_result_t *curr, int curr_count) {
    char rel[64];
    format_relative_time(prev_when, rel, sizeof(rel));

    printf("\n=== Change Detection (baseline: %s) ===\n", rel);

    int i = 0, j = 0;
    int new_count = 0, closed_count = 0, changed_count = 0, unchanged_count = 0;

    /* Both arrays are pre-sorted ascending by port, so a linear
     * two-pointer merge finds every NEW / CLOSED / CHANGED port in a
     * single O(n) pass - the same technique `diff` uses on sorted input. */
    while (i < prev_count && j < curr_count) {
        if (prev[i].port < curr[j].port) {
            printf("  - closed   %-6d (was: %s)\n", prev[i].port, prev[i].banner);
            closed_count++;
            i++;
        } else if (prev[i].port > curr[j].port) {
            printf("  + new      %-6d %s\n", curr[j].port, curr[j].banner);
            new_count++;
            j++;
        } else {
            if (strcmp(prev[i].banner, curr[j].banner) != 0) {
                printf("  ~ changed  %-6d '%s' -> '%s'\n",
                       curr[j].port, prev[i].banner, curr[j].banner);
                changed_count++;
            } else {
                unchanged_count++;
            }
            i++; j++;
        }
    }
    while (i < prev_count) {
        printf("  - closed   %-6d (was: %s)\n", prev[i].port, prev[i].banner);
        closed_count++; i++;
    }
    while (j < curr_count) {
        printf("  + new      %-6d %s\n", curr[j].port, curr[j].banner);
        new_count++; j++;
    }

    if (new_count == 0 && closed_count == 0 && changed_count == 0) {
        printf("  no changes (%d port%s unchanged)\n",
               unchanged_count, unchanged_count == 1 ? "" : "s");
    } else {
        printf("  summary: %d new, %d closed, %d changed, %d unchanged\n",
               new_count, closed_count, changed_count, unchanged_count);
    }
}
