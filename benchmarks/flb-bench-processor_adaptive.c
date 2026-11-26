/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Benchmark for the adaptive processor core, without the pipeline around it.
 *
 *   assign FILE [similarity] [depth]
 *       print the pattern serial chosen for every line, used to score the
 *       miner against labelled datasets
 *
 *   bench FILE [repeat] [lines_per_second] [sample_mode] [window] [allow]
 *       time the miner alone and the miner plus the decision engine, the
 *       clock advances as if lines arrived at the given rate
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif

#include "../plugins/processor_adaptive/adaptive_miner.h"
#include "../plugins/processor_adaptive/adaptive_policy.h"

struct corpus {
    char *data;
    size_t size;
    char **lines;
    size_t *lens;
    size_t count;
    size_t bytes;
};

static int corpus_load(struct corpus *corpus, const char *path)
{
    long size;
    size_t i;
    size_t start = 0;
    size_t count = 0;
    FILE *fp;

    memset(corpus, 0, sizeof(struct corpus));

    fp = fopen(path, "rb");
    if (!fp) {
        perror(path);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    corpus->data = flb_malloc(size + 1);
    if (!corpus->data || fread(corpus->data, 1, size, fp) != (size_t) size) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    corpus->size = size;

    for (i = 0; i < corpus->size; i++) {
        if (corpus->data[i] == '\n') {
            count++;
        }
    }
    if (corpus->size > 0 && corpus->data[corpus->size - 1] != '\n') {
        count++;
    }

    corpus->lines = flb_calloc(count ? count : 1, sizeof(char *));
    corpus->lens = flb_calloc(count ? count : 1, sizeof(size_t));
    if (!corpus->lines || !corpus->lens) {
        return -1;
    }

    for (i = 0; i <= corpus->size; i++) {
        if (i < corpus->size && corpus->data[i] != '\n') {
            continue;
        }
        if (i == corpus->size && start == i) {
            break;
        }
        corpus->lines[corpus->count] = corpus->data + start;
        corpus->lens[corpus->count] = i - start;
        corpus->bytes += i - start;
        corpus->count++;
        start = i + 1;
    }

    return 0;
}

/* Heap bytes in use, 0 where the allocator cannot tell */
static size_t heap_in_use()
{
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    struct mallinfo2 info = mallinfo2();

    return info.uordblks;
#else
    return 0;
#endif
}

static double seconds_now()
{
    struct flb_time tm;

    flb_time_get(&tm);
    return flb_time_to_double(&tm);
}

static int cmd_assign(int argc, char **argv)
{
    int is_new;
    int changed;
    size_t i;
    double similarity = argc > 3 ? atof(argv[3]) : 0.5;
    int depth = argc > 4 ? atoi(argv[4]) : 4;
    struct corpus corpus;
    struct adaptive_miner *miner;
    struct adaptive_pattern *pattern;

    if (corpus_load(&corpus, argv[2]) != 0) {
        return 1;
    }

    miner = adaptive_miner_create(similarity, depth, 100, 64, 1000000);
    if (!miner) {
        fprintf(stderr, "invalid miner settings\n");
        return 1;
    }

    for (i = 0; i < corpus.count; i++) {
        pattern = adaptive_miner_process(miner, corpus.lines[i], corpus.lens[i],
                                         i + 1, &is_new, &changed);
        if (!pattern) {
            return 1;
        }
        printf("%" PRIu64 "\n", pattern->serial);
    }

    adaptive_miner_destroy(miner);
    return 0;
}

static int cmd_bench(int argc, char **argv)
{
    int r;
    int is_new;
    int changed;
    int repeat = argc > 3 ? atoi(argv[3]) : 10;
    double rate = argc > 4 ? atof(argv[4]) : 10000.0;
    const char *mode_name = argc > 5 ? argv[5] : "log";
    int window = argc > 6 ? atoi(argv[6]) : 30;
    int allow = argc > 7 ? atoi(argv[7]) : 10;
    int mode;
    size_t i;
    uint64_t now;
    uint64_t step;
    uint64_t total;
    uint64_t kept = 0;
    uint64_t dropped = 0;
    uint64_t bytes_dropped = 0;
    size_t heap_before;
    size_t heap_after;
    double start;
    double mine_seconds;
    double full_seconds;
    struct corpus corpus;
    struct adaptive_miner *miner;
    struct adaptive_policy *policy;
    struct adaptive_pattern *pattern;
    struct adaptive_decision decision;

    mode = adaptive_policy_sample_mode(mode_name);
    if (corpus_load(&corpus, argv[2]) != 0 || repeat < 1 || rate <= 0 || mode < 0) {
        fprintf(stderr, "invalid arguments\n");
        return 1;
    }
    total = (uint64_t) corpus.count * repeat;
    step = (uint64_t) (1000000000.0 / rate);

    /* miner alone */
    miner = adaptive_miner_create(0.5, 4, 100, 64, 2000);
    start = seconds_now();
    for (r = 0; r < repeat; r++) {
        for (i = 0; i < corpus.count; i++) {
            adaptive_miner_process(miner, corpus.lines[i], corpus.lens[i],
                                   1, &is_new, &changed);
        }
    }
    mine_seconds = seconds_now() - start;
    adaptive_miner_destroy(miner);

    /* miner and decisions on a simulated clock */
    heap_before = heap_in_use();
    miner = adaptive_miner_create(0.5, 4, 100, 64, 2000);
    policy = adaptive_policy_create(window, allow, 30, mode, 100, 0);
    now = 1700000000ULL * 1000000000ULL;
    start = seconds_now();
    for (r = 0; r < repeat; r++) {
        for (i = 0; i < corpus.count; i++) {
            now += step;
            pattern = adaptive_miner_process(miner, corpus.lines[i], corpus.lens[i],
                                             now, &is_new, &changed);
            adaptive_policy_decide(policy, pattern, corpus.lens[i], now, FLB_FALSE,
                                   &decision);
            if (decision.action == ADAPTIVE_KEEP) {
                kept++;
            }
            else {
                dropped++;
                bytes_dropped += corpus.lens[i];
            }
        }
    }
    full_seconds = seconds_now() - start;
    heap_after = heap_in_use();

    printf("{\"lines\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"patterns\":%d"
           ",\"state_bytes\":%zu"
           ",\"mine_lines_per_sec\":%.0f,\"mine_mb_per_sec\":%.1f"
           ",\"mine_ns_per_line\":%.0f"
           ",\"full_lines_per_sec\":%.0f,\"full_mb_per_sec\":%.1f"
           ",\"full_ns_per_line\":%.0f"
           ",\"kept\":%" PRIu64 ",\"dropped\":%" PRIu64
           ",\"record_reduction\":%.4f,\"byte_reduction\":%.4f}\n",
           total, (uint64_t) corpus.bytes * repeat, miner->pattern_count,
           heap_after - heap_before,
           total / mine_seconds, corpus.bytes * repeat / mine_seconds / 1048576.0,
           mine_seconds * 1e9 / total,
           total / full_seconds, corpus.bytes * repeat / full_seconds / 1048576.0,
           full_seconds * 1e9 / total,
           kept, dropped,
           (double) dropped / total,
           (double) bytes_dropped / ((double) corpus.bytes * repeat));

    adaptive_policy_destroy(policy);
    adaptive_miner_destroy(miner);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "assign") == 0) {
        return cmd_assign(argc, argv);
    }
    if (argc >= 3 && strcmp(argv[1], "bench") == 0) {
        return cmd_bench(argc, argv);
    }

    fprintf(stderr,
            "usage: %s assign FILE [similarity] [depth]\n"
            "       %s bench FILE [repeat] [lines_per_second] [sample_mode] "
            "[window] [allow]\n", argv[0], argv[0]);
    return 1;
}
