/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cfl/cfl_time.h>
#include <fluent-bit/flb_output_throttle.h>

#define DEFAULT_ITERATIONS 1000000
#define CONTENTION_THREADS 4

struct benchmark_worker {
    uint64_t iterations;
    uint64_t admitted;
    struct flb_output_throttle *gate;
};

static void *run_admissions(void *data)
{
    uint64_t index;
    uint64_t generation;
    struct benchmark_worker *worker;

    worker = data;
    for (index = 0; index < worker->iterations; index++) {
        worker->admitted += flb_output_throttle_admit(
                                worker->gate,
                                flb_output_throttle_now_ms(),
                                &generation);
    }

    return NULL;
}

static double elapsed_seconds(uint64_t start, uint64_t end)
{
    return (double) (end - start) / 1000000000.0;
}

static void report(const char *name, uint64_t operations, double seconds)
{
    printf("%-30s %12" PRIu64 " ops %10.3f Mops/s\n",
           name, operations, (double) operations / seconds / 1000000.0);
}

static double run_parallel(struct flb_output_throttle *gate,
                           uint64_t iterations)
{
    int index;
    int created;
    uint64_t start;
    uint64_t end;
    pthread_t threads[CONTENTION_THREADS];
    struct benchmark_worker workers[CONTENTION_THREADS];

    created = 0;
    start = cfl_time_now();
    for (index = 0; index < CONTENTION_THREADS; index++) {
        workers[index].iterations = iterations;
        workers[index].admitted = 0;
        workers[index].gate = gate;
        if (pthread_create(&threads[index], NULL,
                           run_admissions, &workers[index]) != 0) {
            break;
        }
        created++;
    }
    for (index = 0; index < created; index++) {
        pthread_join(threads[index], NULL);
    }
    end = cfl_time_now();

    if (created != CONTENTION_THREADS) {
        return -1.0;
    }
    return elapsed_seconds(start, end);
}

static void report_overhead(const char *name, double baseline, double candidate)
{
    printf("%-30s %10.2f%%\n", name,
           (candidate / baseline - 1.0) * 100.0);
}

int main(int argc, char **argv)
{
    uint64_t iterations;
    uint64_t start;
    uint64_t end;
    uint64_t generation;
    double disabled_seconds;
    double enabled_seconds;
    double disabled_parallel_seconds;
    double enabled_parallel_seconds;
    volatile uint64_t baseline;
    struct benchmark_worker workers[CONTENTION_THREADS];
    struct flb_output_throttle disabled_gate;
    struct flb_output_throttle enabled_gate;

    iterations = DEFAULT_ITERATIONS;
    if (argc > 1) {
        iterations = strtoull(argv[1], NULL, 10);
    }
    if (iterations == 0) {
        fprintf(stderr, "iterations must be greater than zero\n");
        return EXIT_FAILURE;
    }

    if (flb_output_throttle_init(&disabled_gate,
                                 FLB_FALSE, 1000, 60000) != 0) {
        fprintf(stderr, "could not initialize throttle gates\n");
        return EXIT_FAILURE;
    }
    if (flb_output_throttle_init(&enabled_gate,
                                 FLB_TRUE, 1000, 60000) != 0) {
        fprintf(stderr, "could not initialize throttle gates\n");
        flb_output_throttle_destroy(&disabled_gate);
        return EXIT_FAILURE;
    }

    baseline = 0;
    start = cfl_time_now();
    for (generation = 0; generation < iterations; generation++) {
        baseline += flb_output_throttle_now_ms() != UINT64_MAX;
    }
    end = cfl_time_now();
    report("clock-only baseline", iterations, elapsed_seconds(start, end));

    workers[0].iterations = iterations;
    workers[0].admitted = 0;
    workers[0].gate = &disabled_gate;
    start = cfl_time_now();
    run_admissions(&workers[0]);
    end = cfl_time_now();
    disabled_seconds = elapsed_seconds(start, end);
    report("disabled gate", iterations, disabled_seconds);

    workers[0].admitted = 0;
    workers[0].gate = &enabled_gate;
    start = cfl_time_now();
    run_admissions(&workers[0]);
    end = cfl_time_now();
    enabled_seconds = elapsed_seconds(start, end);
    report("enabled ready gate", iterations, enabled_seconds);
    report_overhead("enabled vs disabled overhead",
                    disabled_seconds, enabled_seconds);

    disabled_parallel_seconds = run_parallel(&disabled_gate, iterations);
    enabled_parallel_seconds = run_parallel(&enabled_gate, iterations);
    if (disabled_parallel_seconds < 0 || enabled_parallel_seconds < 0) {
        fprintf(stderr, "could not create benchmark threads\n");
        flb_output_throttle_destroy(&enabled_gate);
        flb_output_throttle_destroy(&disabled_gate);
        return EXIT_FAILURE;
    }
    report("disabled gate, 4 threads", iterations * CONTENTION_THREADS,
           disabled_parallel_seconds);
    report("enabled ready gate, 4 threads",
           iterations * CONTENTION_THREADS, enabled_parallel_seconds);
    report_overhead("4-thread enabled overhead",
                    disabled_parallel_seconds, enabled_parallel_seconds);

    flb_output_throttle_destroy(&enabled_gate);
    flb_output_throttle_destroy(&disabled_gate);
    return baseline == 0;
}
