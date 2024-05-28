/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef __wasi__
#error This example only compiles to WASM/WASI target
#endif

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned prime_numbers_count = 0;

bool
is_prime(unsigned int num)
{
    for (unsigned int i = 2; i <= (unsigned int)(sqrt(num)); ++i) {
        if (num % i == 0) {
            return false;
        }
    }

    return true;
}

void *
check_if_prime(void *value)
{
    unsigned int *num = (unsigned int *)(value);
    usleep(10000);
    if (is_prime(*num)) {
        __atomic_fetch_add(&prime_numbers_count, 1, __ATOMIC_SEQ_CST);
    }
    return NULL;
}

unsigned int
validate(int iter_num)
{
    unsigned int counter = 0;
    for (unsigned int i = 2; i <= iter_num; ++i) {
        counter += is_prime(i);
    }

    return counter;
}

void
spawn_thread(pthread_t *thread, int retry_time_us, int retry_num,
             unsigned int *arg)
{
    int status_code = -1;
    int timeout_us = retry_time_us;
    for (int tries = 0; status_code != 0 && tries < retry_num; ++tries) {
        status_code = pthread_create(thread, NULL, &check_if_prime, arg);
        assert(status_code == 0 || status_code == EAGAIN);
        if (status_code == EAGAIN) {
            usleep(timeout_us);
            timeout_us *= 2;
        }
    }

    assert(status_code == 0 && "Thread creation should succeed");
}

void
test(int iter_num, int retry_num, int max_threads_num, int retry_time_us)
{
    pthread_t threads[max_threads_num];
    unsigned int args[max_threads_num];
    double percentage = 0.1;

    for (unsigned int factorised_number = 2; factorised_number < iter_num;
         ++factorised_number) {
        if (factorised_number > iter_num * percentage) {
            fprintf(stderr, "Stress test is %d%% finished\n",
                    (unsigned int)(percentage * 100));
            percentage += 0.1;
        }

        unsigned int thread_num = factorised_number % max_threads_num;
        if (threads[thread_num] != 0) {
            assert(pthread_join(threads[thread_num], NULL) == 0);
        }

        args[thread_num] = factorised_number;

        usleep(retry_time_us);
        spawn_thread(&threads[thread_num], retry_time_us, retry_num,
                     &args[thread_num]);
        assert(threads[thread_num] != 0);
    }

    for (int i = 0; i < max_threads_num; ++i) {
        assert(threads[i] == 0 || pthread_join(threads[i], NULL) == 0);
    }

    // Check the test results
    assert(
        prime_numbers_count == validate(iter_num)
        && "Answer mismatch between tested code and reference implementation");

    fprintf(stderr, "Stress test finished successfully\n");
}

enum DEFAULT_PARAMETERS {
    ITER_NUM = 20000,
    RETRY_NUM = 8,
    MAX_THREADS_NUM = 12,
    RETRY_SLEEP_TIME_US = 2000,
};

int
main(int argc, char **argv)
{
    test(ITER_NUM, RETRY_NUM, MAX_THREADS_NUM, RETRY_SLEEP_TIME_US);
    return 0;
}
