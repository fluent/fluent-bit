/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_pipe.h>

#ifdef FLB_HAVE_BUFFERING

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <dirent.h>

#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

#include <monkey/mk_core.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_buffer_chunk.h>
#include <fluent-bit/flb_buffer_qchunk.h>
#include <fluent-bit/flb_sha1.h>

/* Local structure used to validate and obtain Chunk information */
struct chunk_info {
    char hash_str[41];
    uint64_t routes;
    int worker_id;
    uint8_t full_scan;
    char *tag;
};

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
            worker = NULL;
            i++;
        }
    }

    return worker;
}

/* Given a Chunk filename, validate format and populate chunk_info structure */
int chunk_info(char *filename, struct chunk_info *info)
{
    int i;
    int len;
    char *p;
    char *tmp;
    char num[9];

    len = strlen(filename);
    if (len < 47) {
        return -1;
    }

    /* Validate Hash number */
    for (i = 0; i < 40; i++) {
        if (!isxdigit(filename[i])) {
            return -1;
        }
    }

    /* Lookup routes number */
    if (filename[40] != '.') {
        return -1;
    }

    tmp = filename + 41;
    p = strchr(tmp, '.');
    if (!p) {
        return -1;
    }
    memcpy(info->hash_str, filename, 40);
    info->hash_str[40] = '\0';

    len = (p - tmp);
    if (len < 1 || len > sizeof(num) - 1) {
        return -1;
    }
    strncpy(num, tmp, len);
    num[len] = '\0';

    for (i = 0; i < len; i++) {
        if (!isdigit(num[i])) {
            return -1;
        }
    }
    info->routes = atol(num);

    /* Worker ID */
    p++;
    if (*p != 'w') {
        return -1;
    }
    tmp = ++p;
    p = strchr(tmp, '.');
    if (!p) {
        return -1;
    }
    len = (p - tmp);

    if (len < 1 || len > sizeof(num) - 1) {
        return -1;
    }
    strncpy(num, tmp, len);
    num[len] = '\0';

    for (i = 0; i < len; i++) {
        if (!isdigit(num[i])) {
            return -1;
        }
    }
    info->worker_id = atol(num);

    /* Tag */
    p++;
    if (!isalpha(*p)) {
        return -1;
    }
    info->tag = p;

    return 0;
}

void request_destroy(struct flb_buffer_request *req)
{
    mk_list_del(&req->_head);
    flb_free(req);
}

/* Given a chunk Hash and a root directory, lookup the absolute path if found */
static int chunk_find(char *root_path, char *hash,
                      char **abs_path, char **real_name)
{
    int ret;
    int root_len;
    int file_len;
    int target_len;
    char *target;
    char *file = NULL;
    struct dirent *entry;
    DIR *dir;

    dir = opendir(root_path);
    if (!dir) {
        flb_errno();
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        ret = strncmp(entry->d_name, hash, 40);
        if (ret == 0) {
            file = flb_strdup(entry->d_name);
            if (!file) {
                closedir(dir);
                return -1;
            }
            break;
        }
        file = NULL;
    }
    closedir(dir);

    if (!file) {
        return -1;
    }

    root_len = strlen(root_path);
    file_len = strlen(file);
    if ((file_len + root_len + 1) > PATH_MAX) {
        flb_free(file);
        return -1;
    }

    target = flb_malloc(PATH_MAX);
    if (!target) {
        flb_free(file);
        return -1;
    }

    memcpy(target, root_path, root_len);
    target_len = root_len;
    memcpy(target + target_len, file, file_len);
    target_len += file_len;
    target[target_len] = '\0';

    *abs_path = target;
    *real_name = file;

    return 0;
}

/*
 * Remove a route from a Chunk file. This is done altering the filename,
 * specifically altering the the mask number.
 */
static int chunk_remove_route(char *root_path, char *abs_path,
                              char *hash, struct chunk_info *info,
                              uint64_t mask_id)
{
    int ret;
    int len_path;
    char *to = NULL;
    uint64_t routes;

    /* We may need to delete this chunk right-away */
    routes = (info->routes & ~mask_id);
    if (routes == 0) {
        flb_debug("[buffer] delete chunk %s", abs_path);
        ret = unlink(abs_path);
        if (ret == -1) {
            flb_errno();
            return -1;
        }
        return 0;
    }

    /* Alter route renaming the chunk file */
    len_path = strlen(root_path);
    if ((len_path + 1) > PATH_MAX) {
        return -1;
    }

    to = flb_malloc(PATH_MAX);
    if (!to) {
        flb_errno();
        return -1;
    }

    snprintf(to, PATH_MAX - 1, "%s/%s.%lu.w%i.%s",
             root_path,
             hash, routes, info->worker_id, info->tag);

    flb_debug("[buffer] rename chunk %s to %s",
              abs_path, to);

    ret = rename(abs_path, to);
    if (ret == -1) {
        flb_errno();
        flb_free(to);
        return -1;
    }
    flb_free(to);

    return 0;
}

/* Handle the exception of a missing Chunk file in a Task directory */
static int chunk_miss(struct flb_buffer_worker *worker, uint64_t mask_id,
                      char *hash_hex)
{
    int ret;
    char *target = NULL;
    char *real_name = NULL;
    char root_path[PATH_MAX];
    struct chunk_info info;

    /* Try to find the file in the outgoing queue */
    snprintf(root_path, sizeof(root_path) - 1,
             "%soutgoing/",
             FLB_BUFFER_PATH(worker));

    ret = chunk_find(root_path, hash_hex, &target, &real_name);
    if (ret == 0) {
        /*
         * The chunk was found in the 'outgoing' queue, we need to get
         * more chunk details and remove the reference between the
         * the Thread and Route associated.
         */
        ret = chunk_info(real_name, &info);
        if (ret != 0) {
            flb_error("[buffer] invalid chunk name %s", real_name);
            flb_free(real_name);
            flb_free(target);
            return -1;
        }

        chunk_remove_route(root_path, target, hash_hex, &info, mask_id);
        flb_free(real_name);
        flb_free(target);
        return 0;
    }

    /* Incoming queue */
    snprintf(root_path, sizeof(root_path) - 1,
             "%sincoming/",
             FLB_BUFFER_PATH(worker));

    ret = chunk_find(root_path, hash_hex, &target, &real_name);
    if (ret == 0) {
        ret = chunk_info(real_name, &info);
        if (ret != 0) {
            flb_error("[buffer] invalid chunk name %s", real_name);
            flb_free(real_name);
            flb_free(target);
            return -1;
        }
        chunk_remove_route(root_path, target, hash_hex, &info, mask_id);
        flb_free(real_name);
        flb_free(target);
    }

    return 0;
}

/*
 * When the Worker (thread) receives a FLB_BUFFER_EV_ADD event, this routine
 * read the request data and store the chunk into the file system.
 *
 * The buffer chunk filename format is:
 *
 *    SHA1(chunk.data).ROUTER_MASK_ID.WORKER_ID.TAG
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
    ret = flb_pipe_read_all(worker->ch_add[0], &chunk,
                            sizeof(struct flb_buffer_chunk));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    /*
     * Chunk file format:
     *
     *     SHA1(chunk.data).routes_id.wID.tag
     */
    fchunk = flb_malloc(PATH_MAX);
    if (!fchunk) {
        flb_errno();
        return -1;
    }

    ret = snprintf(fchunk, PATH_MAX - 1,
                   "%s.%lu.w%i.%s",
                   chunk.hash_hex,
                   chunk.routes,
                   worker->id, chunk.tmp);
    if (ret == -1) {
        flb_errno();
        flb_free(fchunk);
        return -1;
    }

    ret = snprintf(target, sizeof(target) - 1,
                   "%s/incoming/%s",
                   FLB_BUFFER_PATH(worker), fchunk);
    if (ret == -1) {
        flb_errno();
        flb_free(fchunk);
        return -1;
    }

    f = fopen(target, "w");
    if (!f) {
        flb_errno();
        flb_free(fchunk);
        return -1;
    }

    /* Lock this file */
    fd = fileno(f);
    ret = flock(fd, LOCK_EX);
    if (ret == -1) {
        flb_errno();
        fclose(f);
        flb_free(fchunk);
        return -1;
    }

    /* Write data chunk */
    w = fwrite(chunk.data, chunk.size, 1, f);
    if (!w) {
        flb_errno();
        fclose(f);
        flb_free(fchunk);
        return -1;
    }

    /* Unlock and close */
    flock(fd, LOCK_UN);

    /* Double check target file */
    ret = fstat(fd, &st);
    if (ret == -1) {
        fprintf(stderr, "[buffer] chunk check failed %lu/%lu bytes",
                st.st_size, chunk.size);
        fclose(f);
        flb_free(fchunk);
        return -1;
    }

    fclose(f);
    *filename = fchunk;
    return chunk.routes;
}


/* Delete a physical reference of a task chunk */
int flb_buffer_chunk_delete(struct flb_buffer_worker *worker,
                            struct mk_event *event)
{
    int ret;
    int remaining;
    char *target = NULL;
    char *real_name = NULL;
    char path[PATH_MAX];
    struct mk_list *head;
    struct flb_output_instance *o_ins;
    struct flb_buffer_chunk chunk;
    struct flb_config *config;
    struct chunk_info info;
    struct stat st;

    /* Read the expected chunk reference */
    ret = flb_pipe_r(worker->ch_del[0], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret <= 0) {
        flb_errno();
        return -1;
    }

    /* Lookup file */
    snprintf(path, sizeof(path) - 1, "%s/outgoing/",
             FLB_BUFFER_PATH(worker));
    ret = chunk_find(path, chunk.hash_hex, &target, &real_name);
    if (ret != 0) {
        flb_error("[buffer] could not match task %s/%s",
                  chunk.tmp, chunk.hash_hex);
        return -1;
    }

    /* Get chunk info */
    ret = chunk_info(real_name, &info);
    if (ret == -1) {
        flb_free(target);
        flb_free(real_name);
        return -1;
    }

    /*
     * At this step we need to determinate if any Task is associated to the
     * buffer chunk in question, if so do nothing, otherwise if no remaining
     * Tasks associated exists we can delete the original Buffer from the
     * outgoing queue path.
     */

    remaining = 0;
    config = worker->parent->config;

    /* Iterate output instances (Tasks paths) */
    mk_list_foreach(head, &config->outputs) {
        o_ins = mk_list_entry(head, struct flb_output_instance, _head);
        snprintf(path, sizeof(path) - 1, "%stasks/%s/%s",
                 FLB_BUFFER_PATH(worker),
                 o_ins->name,
                 real_name);
        ret = stat(path, &st);
        if (ret == 0 && S_ISREG(st.st_mode)) {
            remaining++;
            break;
        }
    }

    if (remaining == 0) {
        snprintf(path, sizeof(path) - 1, "%soutgoing/%s",
                 FLB_BUFFER_PATH(worker),
                 real_name);
        ret = unlink(path);
        if (ret == -1) {
            flb_errno();
            flb_free(target);
            flb_free(real_name);
            return -1;
        }
    }

    flb_free(target);
    flb_free(real_name);

    return 0;
}


/* Delete a physical reference of a task chunk */
int flb_buffer_chunk_delete_ref(struct flb_buffer_worker *worker,
                                struct mk_event *event)
{
    int ret;
    char *target;
    char *real_name;
    char root_path[PATH_MAX];
    struct flb_buffer_chunk chunk;
    struct flb_output_instance *o_ins;

    /* Read the expected chunk reference */
    ret = flb_pipe_read_all(worker->ch_del_ref[0], &chunk,
                            sizeof(struct flb_buffer_chunk));
    if (ret <= 0) {
        flb_errno();
        return FLB_BUFFER_ERROR;
    }

    /* Compose the absolute directory for the target reference */
    ret = snprintf(root_path, sizeof(root_path) - 1,
                   "%stasks/%s/",
                   FLB_BUFFER_PATH(worker),
                   chunk.tmp);
    if (ret == -1) {
        flb_errno();
        return FLB_BUFFER_ERROR;
    }

    /* Find absolute path for given Hash under task root path */
    o_ins = chunk.data;
    ret = chunk_find(root_path, chunk.hash_hex, &target, &real_name);
    if (ret != 0) {
        flb_debug("[buffer] could not match task %s/%s (chunk_miss handler)",
                  chunk.tmp, chunk.hash_hex);
        chunk_miss(worker, o_ins->mask_id, chunk.hash_hex);
        return FLB_BUFFER_NOTFOUND;
    }

    ret = unlink(target);
    if (ret != 0) {
        flb_errno();
        flb_error("[buffer] cannot delete %s", target);
        flb_free(target);
        flb_free(real_name);
        return FLB_BUFFER_ERROR;
    }

    flb_debug("[buffer] removing task %s OK", target);

    flb_free(real_name);
    flb_free(target);

    /*
     * Every time a buffer chunk reference is deleted, we dispatch a
     * request over the ch_del[] channel on this same worker, which
     * aims to delete the real buffer chunk if no one else have
     * a reference to it.
     */
    ret = flb_pipe_w(worker->ch_del[1], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret == -1) {
        flb_errno();
        return FLB_BUFFER_ERROR;
    }

    return FLB_BUFFER_OK;
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
    chunk.tmp[chunk.tmp_len] = '\0';
    memcpy(&chunk.hash_hex, hash_hex, 41);
    chunk.hash_hex[41] = '\0';

    /* Lookup target worker */
    worker = get_worker(ctx, ctx->worker_lru);

    /* Write request through worker channel */
    ret = flb_pipe_w(worker->ch_add[1], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret == -1) {
        flb_errno();
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
                         struct flb_task *task)
{
    int ret;
    struct flb_buffer_chunk chunk;
    struct flb_buffer_worker *worker;
    struct flb_output_instance *o_ins;
    struct flb_output_thread *out_th;

    /*
     * The request must be send to the same buffer worker that originally
     * created the chunk. It must be done on this way to avoid cases
     * where the output plugin finished before the buffer writer is still
     * working (remember: buffer chunks are a backup system).
     */
    worker = get_worker(ctx, task->worker_id);
    out_th = flb_output_thread_get(thread_id, task);
    if (!out_th) {
        return -1;
    }

    o_ins = out_th->o_ins;

    /* Compose buffer chunk instruction */
    memset(&chunk, '\0', sizeof(struct flb_buffer_chunk));
    memcpy(&chunk.hash_hex, task->hash_hex, 41);
    chunk.hash_hex[41] = '\0';
    chunk.tmp_len = strlen(o_ins->name);
    memcpy(&chunk.tmp, o_ins->name, chunk.tmp_len);
    chunk.tmp[chunk.tmp_len] = '\0';
    chunk.data = o_ins;

    /* Write request through worker channel */
    ret = flb_pipe_w(worker->ch_del_ref[1], &chunk, sizeof(struct flb_buffer_chunk));
    if (ret == -1) {
        flb_errno();
        return -1;
    }

    return 0;
}

/* Enqueue a request to move a chunk */
int flb_buffer_chunk_mov(int type, char *name, uint64_t routes,
                         struct flb_buffer_worker *worker)
{
    int ret;
    int len;
    struct flb_buffer_request req = {0};

    req.type = type;

    len = strlen(name);
    if (len + 1 >= sizeof(req.name)) {
        return -1;
    }
    else {
        memcpy(&req.name, name, len);
        req.name[len] = '\0';
    }

    /* Do the request */
    ret = flb_pipe_w(worker->ch_mov[1], &req, sizeof(struct flb_buffer_request));
    if (ret == -1) {
        flb_errno();
        return -1;
    }

    return 0;
}

/*
 * Perform a scan over a buffer path to find buffer chunks not processed. This
 * function is only invoked at start time.
 */
int flb_buffer_chunk_scan(struct flb_buffer *ctx)
{
    int ret;
    int routes;
    char src[PATH_MAX];
    char task[PATH_MAX];
    DIR *dir;
    struct chunk_info info;
    struct dirent *ent;
    struct mk_list *head;
    struct flb_output_instance *o_ins;
    struct flb_buffer_qchunk *qchunk;
    struct stat st;

    ret = snprintf(src, sizeof(src) - 1, "%s/outgoing", ctx->path);
    if (ret == -1) {
        return -1;
    }
    dir = opendir(src);
    if (!dir) {
        flb_errno();
        return -1;
    }

    /* Iterate the outgoing/ path */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') && (strcmp(ent->d_name, "..") != 0)) {
            continue;
        }

        /* Look just for files */
        if (ent->d_type != DT_REG) {
            continue;
        }

        /* Validate chunk file */
        ret = chunk_info(ent->d_name, &info);
        if (ret == -1) {
            flb_warn("[buffer scan] invalid chunk file %s", ent->d_name);
            continue;
        }

        flb_debug("[buffer scan] found %s", info.hash_str);

        ret = snprintf(src, sizeof(src) - 1, "%soutgoing/%s",
                       ctx->path, ent->d_name);
        if (ret == -1) {
            closedir(dir);
            return -1;
        }

        /*
         * We have a valid buffer chunk file, now we need to iterate which
         * pending task is associated. This verification is mandatory as if
         * the chunk was set to go to 3 output destinations and it was just
         * sent to one, we need to process ONLY the remaining ones.
         */
        routes = 0;
        mk_list_foreach(head, &ctx->config->outputs) {
            o_ins = mk_list_entry(head, struct flb_output_instance, _head);
            snprintf(task, sizeof(task) - 1, "%stasks/%s/%s",
                     ctx->path, o_ins->name, ent->d_name);

            /* Check that path exists */
            ret = stat(task, &st);
            if (ret == -1) {
                continue;
            }

            /* Only regular file */
            if (st.st_size != 0 || (!S_ISREG(st.st_mode))) {
                continue;
            }

            routes |= o_ins->mask_id;
        }

        if (routes > 0) {
            qchunk = flb_buffer_qchunk_add(ctx->qworker, src, routes,
                                           info.tag, info.hash_str);
            if (!qchunk) {
                flb_error("[buffer scan] qchunk error for %s", src);
            }
            else {
                flb_debug("[buffer scan] qchunk added for %s",
                          info.hash_str);
            }
        }
    }

    closedir(dir);
    return 0;
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
    ret = flb_pipe_r(worker->ch_mov[0], &req, sizeof(struct flb_buffer_request));
    if (ret <= 0) {
        flb_errno();
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
            flb_errno();
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
            flb_errno();
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
                    flb_errno();
                    continue;
                }
                close(fd);
            }
        }
        return 0;
    }

    return -1;
}

#endif /* !FLB_HAVE_BUFFERING */
