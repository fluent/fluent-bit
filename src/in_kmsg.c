/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <fluent-bit/in_kmsg.h>

int in_kmsg_start()
{
    int fd;
    int bytes;
    char line[1024];

    fd = open(FLB_KMSG_DEV, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    while (1) {
        bytes = read(fd, line, sizeof(line) - 1);

        if (bytes == -1) {
            if (errno == -EPIPE) {
                /* Message overwritten / circular buffer */
                continue;
            }
            break;
        }
        else if (bytes > 0) {
            /* Always set a delimiter to avoid buffer trash */
            line[bytes - 1] = '\0';
            printf("%s\n", line);
        }
    }

    return 0;
}
