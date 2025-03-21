/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <stdlib.h>
#include <sys/time.h>

extern int
iwasm_main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    return iwasm_main(argc, argv);
}

int
time_get_ms()
{
    static struct timeval tv;
    gettimeofday(&tv, NULL);
    long long time_in_mill = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;

    return (int)time_in_mill;
}
