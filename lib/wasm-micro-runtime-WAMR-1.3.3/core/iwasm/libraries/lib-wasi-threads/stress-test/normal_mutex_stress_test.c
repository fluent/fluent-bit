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
    pthread_mutex_init(&mutex, NULL);

    run_common_tests(&mutex);

    fprintf(stderr, "Normal mutex test is completed\n");
    pthread_mutex_destroy(&mutex);
}

int
main()
{
    test();
    return 0;
}
