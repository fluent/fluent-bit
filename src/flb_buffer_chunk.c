/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_BUFFERING

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

#include <mk_core.h>
#include <fluent-bit/flb_buffer.h>

/*
 * When the Worker (thread) receives a FLB_BUFFER_EV_ADD event, this routine
 * read the request data and store the chunk into the file system.
 */
int flb_buffer_chunk_add(struct flb_buffer_worker *worker,
                         struct mk_event *event)
{
    int ret;
    char target[PATH_MAX];
    size_t w;
    FILE *f;
    struct timeval tv;
    struct timezone tz;
    struct flb_buffer_chunk chunk;

    /* Read the expected chunk reference */
    ret = read(worker->ch_add[0], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret <= 0) {
        perror("read");
        return -1;
    }

    /*
     * Chunk file format:
     *
     *     flb.TIMESTAMP.NANOSECONDS.wID.tag
     */
    gettimeofday(&tv, &tz);
    ret = snprintf(target, sizeof(target) - 1,
                   "flb.%lu.%lu.w%i.%s",
                   tv.tv_sec, tv.tv_usec,
                   worker->id, chunk.tag);
    if (ret == -1) {
        perror("snprintf");
        return -1;
    }

    f = fopen(target, "w");
    if (!f) {
        perror("fopen");
        return -1;
    }

    w = fwrite(chunk.data, chunk.size, 1, f);
    if (!w) {
        perror("fwrite");
        fclose(f);
        return -1;
    }
    fclose(f);

    printf("wrote: %lu bytes (from %lu)\n", w, chunk.size);
    return 0;
}

#endif /* !FLB_HAVE_BUFFERING */
