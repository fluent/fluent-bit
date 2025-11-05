/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>

uint64_t
get_time_us()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64_t)ts.tv_sec) * 1000 * 1000 + ((uint64_t)ts.tv_nsec) / 1000;
}

int
main(int argc, char **argv)
{
    uint64_t time_start, time_end;
    struct pollfd fds[2];
    int ret;

    printf("sleep 2 seconds\n");
    time_start = get_time_us();
    ret = sleep(2);
    time_end = get_time_us();

    printf("sleep return %u\n", ret);
    printf("time sleeped: %u\n", (uint32_t)(time_end - time_start));
    if (time_end - time_start < 2 * 1000000) {
        printf("Test sleep failed!\n");
        return -1;
    }

    /* watch stdin for input */
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    /* watch stdout for ability to write */
    fds[1].fd = STDOUT_FILENO;
    fds[1].events = POLLOUT;

    printf("poll with 5 seconds\n");
    ret = poll(fds, 2, 5 * 1000);

    if (ret == -1) {
        perror("poll");
        return 1;
    }

    if (!ret) {
        printf("Test poll failed, %d seconds elapsed!\n", 5);
        return 0;
    }

    if (fds[0].revents & POLLIN)
        printf("stdin is readable\n");

    if (fds[1].revents & POLLOUT)
        printf("stdout is writable\n");

    printf("Test finished\n");
    return 0;
}
