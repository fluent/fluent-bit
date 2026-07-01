/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef MUTEX_COMMON_H
#define MUTEX_COMMON_H

#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

enum Constants {
    NUM_ITER = 250000,
    NUM_THREADS = 12,
    NUM_RETRY = 8,
    RETRY_SLEEP_TIME_US = 1000,
};

// We're counting how many times each thread was called using this array
// Main thread is also counted here so we need to make arrays bigger
typedef struct {
    int tids[NUM_THREADS + 1];
    int calls[NUM_THREADS + 1];
} StatCollector;

typedef struct {
    pthread_mutex_t *mutex;
    StatCollector stat;
    int counter;
    bool is_sleeping;
} MutexCounter;

// This enum defines whether thread should sleep to increase contention
enum SleepState {
    NON_SLEEP = 0,
    SLEEP = 1,
};

void
mutex_counter_init(MutexCounter *mutex_counter, pthread_mutex_t *mutex,
                   enum SleepState is_sleeping)
{
    memset(mutex_counter, 0, sizeof(*mutex_counter));
    mutex_counter->mutex = mutex;
    mutex_counter->is_sleeping = is_sleeping;
}

// This function spawns the thread using exponential retries if it receives
// EAGAIN
static inline void
spawn_thread(pthread_t *tid, void *func, void *arg)
{
    int status_code = -1;
    int timeout_us = RETRY_SLEEP_TIME_US;
    for (int tries = 0; status_code != 0 && tries < NUM_RETRY; ++tries) {
        status_code = pthread_create(tid, NULL, (void *(*)(void *))func, arg);
        assert(status_code == 0 || status_code == EAGAIN);
        if (status_code == EAGAIN) {
            usleep(timeout_us);
            timeout_us *= 2;
        }
    }

    assert(status_code == 0 && "Thread creation should succeed");
}

// This function adds tid to our stat
static inline void
add_to_stat(StatCollector *stat, int tid)
{
    int tid_num = 0;
    for (; tid_num < NUM_THREADS + 1 && stat->tids[tid_num] != 0; ++tid_num) {
        if (stat->tids[tid_num] == tid) {
            stat->calls[tid_num]++;
            return;
        }
    }

    assert(tid_num < NUM_THREADS + 1);
    stat->tids[tid_num] = tid;
    stat->calls[tid_num] = 1;
}

// This function prints number of calls by TID
static inline void
print_stat(StatCollector *stat)
{
    fprintf(stderr, "Thread calls count by TID\n");
    for (int i = 0; i < NUM_THREADS + 1; ++i) {
        if (stat->tids[i] != 0) {
            fprintf(stderr, "TID: %d; Calls: %d\n", stat->tids[i],
                    stat->calls[i]);
        }
    }
}

// This function is run by the threads, it increases counter in a loop and then
// sleeps after unlocking the mutex to provide better contention
static inline void *
inc_shared_variable(void *arg)
{
    MutexCounter *mutex_counter = (MutexCounter *)(arg);
    int sleep_us = 0;
    while (!pthread_mutex_lock(mutex_counter->mutex)
           && mutex_counter->counter < NUM_ITER) {
        mutex_counter->counter++;
        add_to_stat(&mutex_counter->stat, (int)(pthread_self()));
        if (mutex_counter->is_sleeping) {
            sleep_us = rand() % 1000;
        }

        assert(pthread_mutex_unlock(mutex_counter->mutex) == 0
               && "Should be able to unlock a mutex");
        if (mutex_counter->is_sleeping) {
            usleep(sleep_us);
        }
    }

    assert(mutex_counter->counter == NUM_ITER);
    assert(pthread_mutex_unlock(mutex_counter->mutex) == 0
           && "Should be able to unlock the mutex after test execution");

    return NULL;
}

// Locking and unlocking a mutex in a single thread.
static inline void *
same_thread_lock_unlock_test(void *mutex)
{
    for (int i = 0; i < NUM_ITER; ++i) {
        assert(pthread_mutex_lock(mutex) == 0
               && "Main thread should be able to lock a mutex");
        assert(pthread_mutex_unlock(mutex) == 0
               && "Main thread should be able to unlock a mutex");
    }

    return NULL;
}

// This function spawns a thread that locks and unlocks a mutex `NUM_ITER` times
// in a row
static inline void
same_non_main_thread_lock_unlock_test(pthread_mutex_t *mutex)
{
    pthread_t tid = 0;
    spawn_thread(&tid, same_thread_lock_unlock_test, mutex);

    assert(tid != 0 && "TID can't be 0 after successful thread creation");
    assert(pthread_join(tid, NULL) == 0
           && "Thread should be joined successfully");
}

// This function checks basic contention between main and non-main thread
// increasing the shared variable
static inline void
two_threads_inc_test(pthread_mutex_t *mutex)
{
    MutexCounter mutex_counter;
    mutex_counter_init(&mutex_counter, mutex, false);

    pthread_t tid = 0;
    spawn_thread(&tid, inc_shared_variable, &mutex_counter);

    assert(tid != 0 && "TID can't be 0 after successful thread creation");
    inc_shared_variable(&mutex_counter);
    assert(pthread_join(tid, NULL) == 0
           && "Thread should be joined without errors");
    assert(mutex_counter.counter == NUM_ITER);
}

// This function creates number of threads specified by NUM_THREADS and run
// concurrent increasing of shared variable
static inline void
max_threads_inc_test(pthread_mutex_t *mutex, int threads_num,
                     enum SleepState is_sleeping)
{
    MutexCounter mutex_counter;
    mutex_counter_init(&mutex_counter, mutex, is_sleeping);

    pthread_t tids[threads_num];
    for (int i = 0; i < threads_num; ++i) {
        spawn_thread(&tids[i], inc_shared_variable, &mutex_counter);
    }

    inc_shared_variable(&mutex_counter);

    for (int i = 0; i < threads_num; ++i) {
        assert(pthread_join(tids[i], NULL) == 0
               && "Thread should be joined without errors");
    }

    print_stat(&mutex_counter.stat);
}

// This function just runs all the tests described above
static inline void
run_common_tests(pthread_mutex_t *mutex)
{
    srand(time(NULL));

    fprintf(stderr, "Starting same_thread_lock_unlock_test test\n");
    same_thread_lock_unlock_test(mutex);
    fprintf(stderr, "Finished same_thread_lock_unlock_test test\n");

    fprintf(stderr, "Starting same_non_main_thread_lock_unlock_test test\n");
    same_non_main_thread_lock_unlock_test(mutex);
    fprintf(stderr, "Finished same_non_main_thread_lock_unlock_test test\n");

    fprintf(stderr, "Starting two_threads_inc_test test\n");
    two_threads_inc_test(mutex);
    fprintf(stderr, "Finished two_threads_inc_test test\n");

    fprintf(stderr, "Starting max_threads_inc_test_sleep test\n");
    max_threads_inc_test(mutex, NUM_THREADS, SLEEP);
    fprintf(stderr, "Finished concurrent_inc sleep test\n");

    fprintf(stderr, "Starting max_threads_inc_test_non_sleep test\n");
    max_threads_inc_test(mutex, NUM_THREADS, NON_SLEEP);
    fprintf(stderr, "Finished max_threads_inc_test test\n");
}

#endif // MUTEX_COMMON_H
