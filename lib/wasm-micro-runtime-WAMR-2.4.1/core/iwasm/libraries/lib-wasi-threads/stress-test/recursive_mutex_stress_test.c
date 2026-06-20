/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <pthread.h>
#include <errno.h>
#include "mutex_common.h"

void
multiple_same_thread_lock(void *mutex)
{
    for (int i = 0; i < 100; ++i) {
        assert(pthread_mutex_lock(mutex) == 0
               && "Recursive mutex should allow multiple locking");
    }

    for (int i = 0; i < 100; ++i) {
        assert(pthread_mutex_unlock(mutex) == 0
               && "Recursive mutex should allow multiple unlocking");
    }
}

void *
same_thread_multiple_rec_mutex_lock(void *mutex)
{
    for (int i = 0; i < NUM_ITER; ++i) {
        multiple_same_thread_lock(mutex);
    }

    return NULL;
}

void
test()
{
    pthread_mutex_t mutex;

    // Set mutex type to recursive. This type allows multiple locking and
    // unlocking within the same thread
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&mutex, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);

    run_common_tests(&mutex);

    fprintf(stderr, "Starting same_thread_multiple_rec_mutex_lock test\n");
    same_thread_multiple_rec_mutex_lock(&mutex);
    fprintf(stderr, "Finished same_thread_multiple_rec_mutex_lock test\n");

    fprintf(stderr, "Starting same_thread_multiple_rec_mutex_lock test in "
                    "non-main thread\n");
    pthread_t tid;
    spawn_thread(&tid, same_thread_multiple_rec_mutex_lock, &mutex);
    assert(pthread_join(tid, NULL) == 0
           && "Non-main thread should be joined successfully");
    fprintf(stderr, "Finished same_thread_multiple_rec_mutex_lock test in "
                    "non-main thread\n");

    fprintf(stderr, "Recursive mutex test is completed\n");
    pthread_mutex_destroy(&mutex);
}

int
main()
{
    test();
    return 0;
}
