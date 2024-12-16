/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

int threads_executed = 0;
unsigned int threads_creation_tried = 0;
unsigned int threads_in_use = 0;

void *
thread_func(void *arg)
{
    (void)(arg);
    __atomic_fetch_add(&threads_executed, 1, __ATOMIC_RELAXED);
    __atomic_fetch_sub(&threads_in_use, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

void
spawn_thread(pthread_t *thread, int retry_time, int iter_num)
{
    int status_code = -1;
    int timeout_us = retry_time;
    for (int tries = 0; status_code != 0 && tries < iter_num; ++tries) {
        status_code = pthread_create(thread, NULL, &thread_func, NULL);
        __atomic_fetch_add(&threads_creation_tried, 1, __ATOMIC_RELAXED);

        assert(status_code == 0 || status_code == EAGAIN);
        if (status_code == EAGAIN) {
            usleep(timeout_us);
            timeout_us *= 2;
        }
    }

    assert(status_code == 0 && "Thread creation should succeed");
}

void
test(int iter_num, int max_threads_num, int retry_num, int retry_time_us)
{
    double percentage = 0.1;
    int second_us = 1000 * 1000 * 1000; // 1 second in us

    for (int iter = 0; iter < iter_num; ++iter) {
        if (iter > iter_num * percentage) {
            fprintf(stderr, "Spawning stress test is %d%% finished\n",
                    (unsigned int)(percentage * 100));
            percentage += 0.1;
        }
        while (__atomic_load_n(&threads_in_use, __ATOMIC_SEQ_CST)
               == max_threads_num) {
            usleep(100);
        }

        __atomic_fetch_add(&threads_in_use, 1, __ATOMIC_SEQ_CST);
        pthread_t tmp;
        spawn_thread(&tmp, retry_time_us, iter_num);
        pthread_detach(tmp);
    }

    while ((__atomic_load_n(&threads_in_use, __ATOMIC_SEQ_CST) != 0)) {
        // Casting to int* to supress compiler warning
        __builtin_wasm_memory_atomic_wait32((int *)(&threads_in_use), 0,
                                            second_us);
    }

    assert(__atomic_load_n(&threads_in_use, __ATOMIC_SEQ_CST) == 0);

    // Validation
    assert(threads_creation_tried >= threads_executed
           && "Test executed more threads than were created");
    assert((1. * threads_creation_tried) / threads_executed < 2.5
           && "Ensuring that we're retrying thread creation less than 2.5 "
              "times on average ");

    fprintf(stderr,
            "Spawning stress test finished successfully executed %d threads "
            "with retry ratio %f\n",
            threads_creation_tried,
            (1. * threads_creation_tried) / threads_executed);
}

enum DEFAULT_PARAMETERS {
    ITER_NUM = 50000,
    RETRY_NUM = 8,
    MAX_NUM_THREADS = 12,
    RETRY_SLEEP_TIME_US = 4000,
};

int
main(int argc, char **argv)
{
    test(ITER_NUM, MAX_NUM_THREADS, RETRY_NUM, RETRY_SLEEP_TIME_US);
    return 0;
}
