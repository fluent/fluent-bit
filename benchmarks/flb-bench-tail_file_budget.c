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

/* Measures the production reservation API without file I/O or log output. */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_pthread.h>
#include "../plugins/in_tail/tail_config.h"
#include "../plugins/in_tail/tail_file_budget.h"

#ifdef FLB_SYSTEM_WINDOWS
#include <Windows.h>
#endif

struct bench_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int ready;
    int start;
    int abort;
};

struct bench_worker {
    struct flb_tail_config ctx;
    struct bench_gate *gate;
    uint64_t iterations;
    uint64_t claims;
    double end;
};

static double monotonic_seconds(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    LARGE_INTEGER count;
    LARGE_INTEGER frequency;

    if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&count)) {
        return -1.0;
    }
    return (double) count.QuadPart / (double) frequency.QuadPart;
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1.0;
    }
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1000000000.0;
#endif
}

static void *claim_worker(void *data)
{
    struct bench_worker *worker = data;
    struct bench_gate *gate = worker->gate;
    uint64_t i;
    uint64_t claims = 0;
    int abort;

    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->start) {
        pthread_cond_wait(&gate->condition, &gate->mutex);
    }
    abort = gate->abort;
    pthread_mutex_unlock(&gate->mutex);

    if (!abort) {
        for (i = 0; i < worker->iterations; i++) {
            if (flb_tail_file_budget_reserve(&worker->ctx)) {
                claims++;
                flb_tail_file_budget_release(&worker->ctx);
            }
        }
    }
    worker->end = monotonic_seconds();
    worker->claims = claims;
    return NULL;
}

static int run_benchmark(const char *mode, int thread_count, uint64_t iterations,
                         int budget, int slots)
{
    int i;
    int input;
    int created = 0;
    uint64_t pinned = 0;
    uint64_t checked = 0;
    int ret = -1;
    int failed = 0;
    int available;
    uint64_t attempts;
    uint64_t claims = 0;
    uint64_t min_claims = UINT64_MAX;
    uint64_t max_claims = 0;
    double start;
    double end;
    double elapsed;
    char limit[32];
    flb_ctx_t *flb;
    struct flb_tail_config ctx = {0};
    struct bench_gate gate = {0};
    struct bench_worker **workers;
    pthread_t *threads;

    available = strcmp(mode, "full") == 0 ? 0 : slots;
    workers = calloc(thread_count, sizeof(*workers));
    threads = calloc(thread_count, sizeof(*threads));
    flb = flb_create();
    if (!workers || !threads || !flb) {
        goto cleanup;
    }
    input = flb_input(flb, "tail", NULL);
    snprintf(limit, sizeof(limit), "%d", budget);
    if (input < 0 || flb_input_set(flb, input, "max_open_files", limit, NULL) != 0) {
        goto cleanup;
    }
    ctx.config = flb->config;
    ctx.ins = mk_list_entry(flb->config->inputs.next, struct flb_input_instance, _head);
    ctx.ins->log_level = FLB_LOG_OFF;
    ctx.file_budget = flb_tail_file_budget_create(&ctx);
    if (!ctx.file_budget) {
        goto cleanup;
    }

    for (i = 0; i < budget - available; i++) {
        if (!flb_tail_file_budget_reserve(&ctx)) {
            goto cleanup;
        }
        pinned++;
    }
    /* Warm up the API and, in full mode, prime the full-warning latch. */
    for (i = 0; i < 1000; i++) {
        if (flb_tail_file_budget_reserve(&ctx)) {
            flb_tail_file_budget_release(&ctx);
        }
    }
    if (pthread_mutex_init(&gate.mutex, NULL) != 0) {
        goto cleanup;
    }
    if (pthread_cond_init(&gate.condition, NULL) != 0) {
        pthread_mutex_destroy(&gate.mutex);
        goto cleanup;
    }
    for (i = 0; i < thread_count; i++) {
        workers[i] = calloc(1, sizeof(*workers[i]));
        if (!workers[i]) {
            break;
        }
        workers[i]->ctx = ctx;
        workers[i]->gate = &gate;
        workers[i]->iterations = iterations;
        if (pthread_create(&threads[i], NULL, claim_worker, workers[i]) != 0) {
            break;
        }
        created++;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < created) {
        pthread_cond_wait(&gate.condition, &gate.mutex);
    }
    start = monotonic_seconds();
    gate.abort = created != thread_count || start < 0.0;
    gate.start = 1;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    end = start;
    for (i = 0; i < created; i++) {
        pthread_join(threads[i], NULL);
        if (workers[i]->end < 0.0) {
            failed = 1;
        }
        if (workers[i]->end > end) {
            end = workers[i]->end;
        }
        claims += workers[i]->claims;
        if (workers[i]->claims < min_claims) {
            min_claims = workers[i]->claims;
        }
        if (workers[i]->claims > max_claims) {
            max_claims = workers[i]->claims;
        }
    }
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    if (gate.abort || failed || end <= start || (available == 0 && claims != 0) ||
        (available > 0 && claims == 0)) {
        fprintf(stderr, "Worker, clock, or admission invariant failed\n");
        goto cleanup;
    }

    /* Outside the timed region, ensure workers leaked no reservations. */
    for (i = 0; i < available; i++) {
        if (!flb_tail_file_budget_reserve(&ctx)) {
            fprintf(stderr, "A worker leaked a reservation\n");
            goto cleanup;
        }
        checked++;
    }
    if (flb_tail_file_budget_reserve(&ctx)) {
        checked++;
        fprintf(stderr, "Shared budget exceeded its configured cap\n");
        goto cleanup;
    }
    elapsed = end - start;
    attempts = iterations * (uint64_t) thread_count;
    printf("%s,%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64
           ",%.6f,%.0f,%.0f,%.3f,%" PRIu64 ",%" PRIu64 "\n",
           mode, thread_count, budget, available, attempts, claims, attempts - claims,
           elapsed, attempts / elapsed, claims / elapsed,
           elapsed * 1000000000.0 / attempts, min_claims, max_claims);
    ret = 0;

cleanup:
    if (ctx.file_budget) {
        while (checked > 0) {
            flb_tail_file_budget_release(&ctx);
            checked--;
        }
        while (pinned > 0) {
            flb_tail_file_budget_release(&ctx);
            pinned--;
        }
        flb_tail_file_budget_destroy(ctx.file_budget);
    }
    if (flb) {
        flb_destroy(flb);
    }
    if (workers) {
        for (i = 0; i < thread_count; i++) {
            free(workers[i]);
        }
    }
    free(workers);
    free(threads);
    return ret;
}

static int positive_integer(const char *value, uint64_t maximum, uint64_t *result)
{
    char *end;
    unsigned long long parsed;

    if (*value < '0' || *value > '9') {
        return -1;
    }
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || *end != '\0' || parsed == 0 || parsed > maximum) {
        return -1;
    }
    *result = parsed;
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [--mode all|full|churn] [--threads 1..256] "
            "[--iterations N] [--budget N] [--slots N]\n", program);
}

int main(int argc, char **argv)
{
    int i;
    uint64_t value;
    uint64_t iterations = 1000000;
    int threads = 4;
    int budget = 1024;
    int slots = 1;
    const char *mode = "all";

    for (i = 1; i < argc; i += 2) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (i + 1 >= argc) {
            goto invalid;
        }
        if (strcmp(argv[i], "--mode") == 0) {
            mode = argv[i + 1];
            continue;
        }
        if (positive_integer(argv[i + 1], UINT64_MAX / 256, &value) != 0) {
            goto invalid;
        }
        if (strcmp(argv[i], "--iterations") == 0) {
            iterations = value;
        }
        else if (strcmp(argv[i], "--threads") == 0 && value <= 256) {
            threads = (int) value;
        }
        else if (strcmp(argv[i], "--budget") == 0 && value <= INT_MAX) {
            budget = (int) value;
        }
        else if (strcmp(argv[i], "--slots") == 0 && value <= INT_MAX) {
            slots = (int) value;
        }
        else {
            goto invalid;
        }
    }
    if (slots > budget || (strcmp(mode, "all") != 0 && strcmp(mode, "full") != 0 &&
                           strcmp(mode, "churn") != 0)) {
        goto invalid;
    }
    puts("mode,threads,budget,available_slots,attempts,claims,rejections,seconds,"
         "attempts_per_second,claims_per_second,wall_ns_per_attempt,min_worker_claims,"
         "max_worker_claims");
    if ((strcmp(mode, "all") == 0 || strcmp(mode, "full") == 0) &&
        run_benchmark("full", threads, iterations, budget, slots) != 0) {
        return EXIT_FAILURE;
    }
    if ((strcmp(mode, "all") == 0 || strcmp(mode, "churn") == 0) &&
        run_benchmark("churn", threads, iterations, budget, slots) != 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;

invalid:
    usage(argv[0]);
    return EXIT_FAILURE;
}
