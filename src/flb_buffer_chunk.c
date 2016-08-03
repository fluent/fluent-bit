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
#include <dirent.h>

#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

#include <mk_core.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_buffer_chunk.h>
#include <fluent-bit/flb_sha1.h>

/* Get a Buffer Worker given it ID */
static struct flb_buffer_worker *get_worker(struct flb_buffer *ctx, int id)
{
    int i;
    struct mk_list *head;
    struct flb_buffer_worker *worker = NULL;

    /* Lookup target worker */
    if (id == 0) {
        worker = mk_list_entry_first(&ctx->workers, struct flb_buffer_worker,
                                     _head);
    }
    else {
        i = 0;
        mk_list_foreach(head, &ctx->workers) {
            if (i == id) {
                worker = mk_list_entry(head, struct flb_buffer_worker, _head);
                break;
            }
            i++;
        }
    }

    return worker;
}

/*
 * When the Worker (thread) receives a FLB_BUFFER_EV_ADD event, this routine
 * read the request data and store the chunk into the file system.
 *
 * The buffer chunk filename format is:
 *
 *    flb.SECONDS.USECONDS.ROUTER_MASK_ID.WORKER_ID.TAG
 *
 * On error it returns -1, otherwise it returns the router mask id. This is
 * used by the caller to 'suggest' outgoing paths when moving the buffer
 * chunk to the 'outgoing' queue.
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
     *     SHA1(chunk.data).routes_id.wID.tag
     */
    fchunk = malloc(PATH_MAX);
    if (!fchunk) {
        perror("malloc");
        return -1;
    }

    ret = snprintf(fchunk, PATH_MAX - 1,
                   "%s.%lu.w%i.%s",
                   chunk.hash_hex,
                   chunk.routes,
                   worker->id, chunk.tmp);
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

    return chunk.routes;
}


/*
 * Delete a physical reference of a Chunk, if no one exists delete the real
 * buffer chunk.
 */
int flb_buffer_chunk_delete(struct flb_buffer_worker *worker,
                            struct mk_event *event)
{
    int ret;
    int target_len;
    int file_len = 0;
    char target[PATH_MAX];
    char *file = NULL;
    struct flb_buffer_chunk chunk;
    DIR *dir;
    struct dirent *entry;

    /* Read the expected chunk reference */
    ret = read(worker->ch_del[0], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret <= 0) {
        perror("read");
        return -1;
    }

    /* Compose the absolute directory for the target reference */
    ret = snprintf(target, sizeof(target) - 1,
                   "%s/tasks/%s/",
                   FLB_BUFFER_PATH(worker),
                   chunk.tmp);
    if (ret == -1) {
        perror("snprintf");
        return -1;
    }
    target_len = ret;

    /* Lookup reference using the Hash number */
    dir = opendir(target);
    if (!dir) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        ret = strncmp(entry->d_name, chunk.hash_hex, 40);
        if (ret == 0) {
            file = malloc(256);
            if (!file) {
                perror("malloc");
                closedir(dir);
                return -1;
            }
            file_len = strlen(entry->d_name);
            memcpy(file, entry->d_name, file_len);
            file[file_len] = '\0';
            break;
        }
    }
    closedir(dir);

    if (!file) {
        flb_error("[buffer] could not match task %s/%s",
                  chunk.tmp, chunk.hash_hex);
        return -1;
    }

    /* Compose final target name */
    if ((target_len + file_len + 1) > sizeof(target)) {
        flb_error("[buffer] cannot compose path, length exceeds limit");
        return -1;
    }

    memcpy(target + target_len, file, file_len);
    target[target_len + file_len] = '\0';
    free(file);

    ret = unlink(target);
    if (ret != 0) {
        perror("unlink");
        flb_error("[buffer] cannot delete %s", target);
        return -1;
    }

    printf("FIXME (flb_debug) [buffer] removing task %s OK\n", target);
    return 0;
}

/*
 * Send a 'chunk create' request to the buffer engine. It return the
 * buffer worker ID that will manage the request.
 */
int flb_buffer_chunk_push(struct flb_buffer *ctx, void *data,
                          size_t size, char *tag, uint64_t routes,
                          char *hash_hex)
{
    int ret;
    struct flb_buffer_chunk chunk;
    struct flb_buffer_worker *worker = NULL;

    /* The buffer engine may be disabled, check that. */
    if (!ctx) {
        return 0;
    }

    /* Define the worker that will handle the buffer (LRU) */
    if (ctx->worker_lru == -1 || (ctx->worker_lru + 1 == ctx->workers_n)) {
        ctx->worker_lru = 0;
    }
    else {
        ctx->worker_lru++;
    }

    /* Compose buffer chunk instruction */
    memset(&chunk, '\0', sizeof(struct flb_buffer_chunk));
    chunk.data       = data;
    chunk.size       = size;
    chunk.tmp_len    = strlen(tag);
    chunk.routes     = routes;
    memcpy(&chunk.tmp, tag, chunk.tmp_len);
    memcpy(&chunk.hash_hex, hash_hex, 41);

    /* Lookup target worker */
    worker = get_worker(ctx, ctx->worker_lru);

    /* Write request through worker channel */
    ret = write(worker->ch_add[1], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret == -1) {
        perror("write");
        return -1;
    }

    flb_debug("[buffer] created records=%p size=%lu worker=%i",
              data, size, ctx->worker_lru);

    return ctx->worker_lru;
}

/*
 * Send a 'chunk destroy' request to the buffer engine, note the request
 * is associated to an outgoing task reference, the real buffer chunk
 * will only be deleted if there is not threads using it.
 */
int flb_buffer_chunk_pop(struct flb_buffer *ctx, int thread_id,
                         struct flb_engine_task *task)
{
    int ret;
    struct flb_buffer_chunk chunk;
    struct flb_buffer_worker *worker;
    struct flb_thread *thread;
    struct flb_output_instance *o_ins;

    /*
     * The request must be send to the same buffer worker that originally
     * created the chunk. It must be done on this way to avoid cases
     * where the output plugin finished before the buffer writer is still
     * working (remember: buffer chunks are a backup system).
     */
    worker = get_worker(ctx, task->worker_id);

    thread = flb_thread_get(thread_id, task);
    o_ins = thread->data;

    /* Compose buffer chunk instruction */
    memset(&chunk, '\0', sizeof(struct flb_buffer_chunk));
    memcpy(&chunk.hash_hex, task->hash_hex, 41);
    chunk.tmp_len = strlen(o_ins->name);
    memcpy(&chunk.tmp, o_ins->name, chunk.tmp_len);

    /* Write request through worker channel */
    ret = write(worker->ch_del[1], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret == -1) {
        perror("write");
        return -1;
    }

    return 0;
}

/* Enqueue a request to move a chunk */
struct flb_buffer_request *flb_buffer_chunk_mov(int type,
                                                char *name,
                                                uint64_t routes,
                                                struct flb_buffer_worker *worker)
{
    int ret;
    struct flb_buffer_request *req;

    req = calloc(1, sizeof(struct flb_buffer_request));
    if (!req) {
        perror("malloc");
        return NULL;
    }

    req->type = type;
    req->name = name;
    mk_list_add(&req->_head, &worker->requests);

    /* Do the request */
    printf("worker pipe ID=%i\n", worker->ch_mov[1]);
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
    int fd;
    int ret;
    uint64_t info_routes;
    char from[PATH_MAX];
    char to[PATH_MAX];
    char hash[41];
    struct mk_list *head;
    struct flb_config *config = worker->parent->config;
    struct flb_output_instance *o_ins;
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
        ret = sscanf(req.name,
                     "%40s.%lu ",
                     hash, &info_routes);
        if (ret == -1) {
            perror("sscanf");
            return -1;
        }
        hash[40] = '\0';

        /* Find output routes and generate file references */
        mk_list_foreach(head, &config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            if (o_ins->mask_id & info_routes) {
                snprintf(to, PATH_MAX - 1,
                         "%s/tasks/%s/%s",
                         FLB_BUFFER_PATH(worker),
                         o_ins->name,
                         req.name);

                fd = open(to, O_CREAT | O_TRUNC, 0666);
                if (fd == -1) {
                    perror("open");
                    continue;
                }
                close(fd);
            }
        }
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
