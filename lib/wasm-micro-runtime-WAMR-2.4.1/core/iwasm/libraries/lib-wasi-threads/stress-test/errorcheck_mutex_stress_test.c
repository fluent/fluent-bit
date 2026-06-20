/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <pthread.h>
#include <errno.h>
#include "mutex_common.h"

void
test()
{
    pthread_mutex_t mutex;

    // Set mutex type to errorcheck. This type provides some additional checks
    // (for example returns EDEADLK instead of deadlocking in some cases)
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_ERRORCHECK);

    pthread_mutex_init(&mutex, &mutex_attr);
    pthread_mutexattr_destroy(&mutex_attr);

    run_common_tests(&mutex);
    fprintf(stderr, "Errorcheck mutex test is completed\n");
    pthread_mutex_destroy(&mutex);
}

int
main()
{
    test();
    return 0;
}
