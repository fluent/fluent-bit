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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

#include <mk_core.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_buffer_chunk.h>

/*
 * When the Worker (thread) receives a FLB_BUFFER_EV_ADD event, this routine
 * read the request data and store the chunk into the file system.
 */
int flb_buffer_chunk_add(struct flb_buffer_worker *worker,
                         struct mk_event *event, char **filename)
{
    int fd;
    int ret;
    char *fchunk;
    char target[PATH_MAX];
    size_t w;
    FILE *f;
    struct timeval tv;
    struct timezone tz;
    struct flb_buffer_chunk chunk;
    struct stat st;

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

    fchunk = malloc(PATH_MAX);
    if (!fchunk) {
        perror("malloc");
        return -1;
    }
    ret = snprintf(fchunk, PATH_MAX - 1, "flb.%lu.%lu.w%i.%s",
                   tv.tv_sec, tv.tv_usec,
                   worker->id, chunk.tag);
    if (ret == -1) {
        perror("snprintf");
        free(fchunk);
        return -1;
    }

    ret = snprintf(target, sizeof(target) - 1,
                   "%s/incoming/%s",
                   FLB_BUFFER_PATH(worker), fchunk);
    if (ret == -1) {
        perror("snprintf");
        free(fchunk);
        return -1;
    }

    f = fopen(target, "w");
    if (!f) {
        perror("fopen");
        free(fchunk);
        return -1;
    }

    /* Lock this file */
    fd = fileno(f);
    ret = flock(fd, LOCK_EX);
    if (ret == -1) {
        perror("flock");
        fclose(f);
        free(fchunk);
        return -1;
    }

    /* Write data chunk */
    w = fwrite(chunk.data, chunk.size, 1, f);
    if (!w) {
        perror("fwrite");
        fclose(f);
        free(fchunk);
        return -1;
    }

    /* Unlock and close */
    flock(fd, LOCK_UN);
    fclose(f);

    /* Double check target file */
    ret = stat(target, &st);
    if (ret == -1) {
        fprintf(stderr, "[buffer] chunk check failed %lu/%lu bytes",
                st.st_size, chunk.size);
        free(fchunk);
        return -1;
    }

    printf("wrote: %lu bytes (from %lu)\n", w, chunk.size);
    *filename = fchunk;
    return 0;
}

/* Enqueue a request to move a chunk */
struct flb_buffer_request *flb_buffer_chunk_mov(int type,
                                                char *name,
                                                struct flb_buffer_worker *worker)
{
    int ret;
    struct flb_buffer_request *req;

    req = malloc(sizeof(struct flb_buffer_request));
    if (!req) {
        perror("malloc");
        return NULL;
    }

    req->type = type;
    req->name = name;
    mk_list_add(&req->_head, &worker->requests);

    /* Do the request */
    ret = write(worker->ch_mov[1], req, sizeof(struct flb_buffer_request));
    if (ret == -1) {
        perror("write");
        return NULL;
    }

    return req;
}

int flb_buffer_chunk_real_move(struct flb_buffer_worker *worker,
                               struct mk_event *event)
{
    int ret;
    char from[PATH_MAX];
    char to[PATH_MAX];
    struct flb_buffer_request req;

    /* Read the expected chunk reference */
    ret = read(worker->ch_mov[0], &req, sizeof(struct flb_buffer_request));
    if (ret <= 0) {
        perror("read");
        return -1;
    }

    /* Move from incoming to outgoing */
    if (req.type == FLB_BUFFER_CHUNK_OUTGOING) {
        snprintf(from, PATH_MAX - 1,
                 "%s/incoming/%s", worker->parent->path, req.name);
        snprintf(to, PATH_MAX - 1,
                 "%s/outgoing/%s", worker->parent->path, req.name);
        ret = rename(from, to);
        if (ret == -1) {
            perror("rename");
            return -1;
        }

        /*
         * Once the chunk is in place, generate the output plugins references
         * (task) to this chunk. A reference is just an empty file in the
         * path 'tasks/PLUGIN_NAME/CHUNK_FILENAME'.
         */
        return 0;
    }

    return -1;
}

void request_destroy(struct flb_buffer_request *req)
{
    mk_list_del(&req->_head);
    free(req);
}

#endif /* !FLB_HAVE_BUFFERING */
