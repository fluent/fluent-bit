/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <libgen.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>
#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash.h>
#endif

#include "tail.h"
#include "tail_file.h"
#include "tail_config.h"
#include "tail_db.h"
#include "tail_signal.h"
#include "tail_dockermode.h"
#include "tail_multiline.h"
#include "tail_scan.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static int unpack_and_pack(msgpack_packer *pck, msgpack_object *root,
                           char *key, size_t key_len,
                           char *val, size_t val_len)
{
    int i;
    int size = root->via.map.size;

    msgpack_pack_map(pck, size + 1);

    /* Append new k/v */
    msgpack_pack_str(pck, key_len);
    msgpack_pack_str_body(pck, key, key_len);
    msgpack_pack_str(pck, val_len);
    msgpack_pack_str_body(pck, val, val_len);

    for (i = 0; i < size; i++) {
        msgpack_object k = root->via.map.ptr[i].key;
        msgpack_object v = root->via.map.ptr[i].val;;

        msgpack_pack_object(pck, k);
        msgpack_pack_object(pck, v);
    }

    return 0;
}

static int append_record_to_map(char **data, size_t *data_size,
                                char *key,  size_t key_len,
                                char *val,  size_t val_len)
{
    int ret;
    msgpack_unpacked result;
    msgpack_object   root;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    size_t off = 0;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    ret = msgpack_unpack_next(&result, *data, *data_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }

    root = result.data;
    ret = unpack_and_pack(&pck, &root,
                          key, key_len, val, val_len);
    if (ret < 0) {
        /* fail! */
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }
    else {
        /* success !*/
        flb_free(*data);
        *data      = sbuf.data;
        *data_size = sbuf.size;
    }

    msgpack_unpacked_destroy(&result);
    return 0;
}

int flb_tail_pack_line_map(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                           struct flb_time *time, char **data,
                           size_t *data_size, struct flb_tail_file *file)
{
    int map_num = 1;

    if (file->config->path_key != NULL) {
        map_num++; /* to append path_key */
    }

    if (file->config->path_key != NULL) {
        append_record_to_map(data, data_size,
                             file->config->path_key,
                             file->config->path_key_len,
                             file->name, file->name_len);
    }

    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(time, mp_pck, 0);
    msgpack_sbuffer_write(mp_sbuf, *data, *data_size);

    return 0;
}

int flb_tail_file_pack_line(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                            struct flb_time *time, char *data, size_t data_size,
                            struct flb_tail_file *file)
{
    int map_num = 1;
    struct flb_tail_config *ctx = file->config;

    if (file->config->path_key != NULL) {
        map_num++; /* to append path_key */
    }
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(time, mp_pck, 0);
    msgpack_pack_map(mp_pck, map_num);

    if (file->config->path_key != NULL) {
        /* append path_key */
        msgpack_pack_str(mp_pck, file->config->path_key_len);
        msgpack_pack_str_body(mp_pck, file->config->path_key,
                              file->config->path_key_len);
        msgpack_pack_str(mp_pck, file->name_len);
        msgpack_pack_str_body(mp_pck, file->name, file->name_len);
    }

    msgpack_pack_str(mp_pck, ctx->key_len);
    msgpack_pack_str_body(mp_pck, ctx->key, ctx->key_len);
    msgpack_pack_str(mp_pck, data_size);
    msgpack_pack_str_body(mp_pck, data, data_size);

    return 0;
}

static int process_content(struct flb_tail_file *file, off_t *bytes)
{
    int len;
    int lines = 0;
    int ret;
    off_t processed_bytes = 0;
    char *data;
    char *end;
    char *p;
    void *out_buf;
    size_t out_size;
    char *line;
    size_t line_len;
    char *repl_line;
    size_t repl_line_len;
    time_t now = time(NULL);
    struct flb_time out_time = {};
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_sbuffer *out_sbuf;
    msgpack_packer *out_pck;
    struct flb_tail_config *ctx = file->config;

    /* Create a temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    out_sbuf = &mp_sbuf;
    out_pck  = &mp_pck;

    /* Parse the data content */
    data = file->buf_data;
    end = data + file->buf_len;
    while ((p = memchr(data, '\n', end - data))) {
        len = (p - data);

        if (file->skip_next == FLB_TRUE) {
            data += len + 1;
            processed_bytes += len;
            file->skip_next = FLB_FALSE;
            continue;
        }

        /* Empty line (just \n) */
        if (len == 0) {
            data++;
            processed_bytes++;
            continue;
        }

        /* Reset time for each line */
        flb_time_zero(&out_time);

        line = data;
        line_len = len;
        repl_line = NULL;

        if (ctx->docker_mode) {
            ret = flb_tail_dmode_process_content(now, line, line_len,
                                                 &repl_line, &repl_line_len,
                                                 file, ctx);
            if (ret >= 0) {
                if (repl_line == line) {
                    repl_line = NULL;
                }
                else {
                    line = repl_line;
                    line_len = repl_line_len;
                }
                if (ret == 0) {
                    goto go_next;
                }
            }
            else {
                flb_tail_dmode_flush(out_sbuf, out_pck, file, ctx);
            }
        }

#ifdef FLB_HAVE_REGEX
        if (ctx->parser) {
            /* Common parser (non-multiline) */
            ret = flb_parser_do(ctx->parser, line, line_len,
                                &out_buf, &out_size, &out_time);
            if (ret >= 0) {
                if (flb_time_to_double(&out_time) == 0) {
                    flb_time_get(&out_time);
                }

                if (ctx->ignore_older > 0) {
                    if ((now - ctx->ignore_older) > out_time.tm.tv_sec) {
                        flb_free(out_buf);
                        goto go_next;
                    }
                }

                /* If multiline is enabled, flush any buffered data */
                if (ctx->multiline == FLB_TRUE) {
                    flb_tail_mult_flush(out_sbuf, out_pck, file, ctx);
                }

                flb_tail_pack_line_map(out_sbuf, out_pck, &out_time,
                                       (char**) &out_buf, &out_size, file);
                flb_free(out_buf);
            }
            else {
                /* Parser failed, pack raw text */
                flb_time_get(&out_time);
                flb_tail_file_pack_line(out_sbuf, out_pck, &out_time,
                                        data, len, file);
            }
        }
        else if (ctx->multiline == FLB_TRUE) {
            ret = flb_tail_mult_process_content(now,
                                                line, line_len, file, ctx);

            /* No multiline */
            if (ret == FLB_TAIL_MULT_NA) {

                flb_tail_mult_flush(out_sbuf, out_pck, file, ctx);

                flb_time_get(&out_time);
                flb_tail_file_pack_line(out_sbuf, out_pck, &out_time,
                                        line, line_len, file);
            }
            else if (ret == FLB_TAIL_MULT_MORE) {
                /* we need more data, do nothing */
                goto go_next;
            }
            else if (ret == FLB_TAIL_MULT_DONE) {
                /* Finalized */
            }
        }
        else {
            flb_time_get(&out_time);
            flb_tail_file_pack_line(out_sbuf, out_pck, &out_time,
                                    line, line_len, file);
        }
#else
        flb_time_get(&out_time);
        flb_tail_file_pack_line(out_sbuf, out_pck, &out_time,
                                line, line_len, file);
#endif

    go_next:
        flb_free(repl_line);
        repl_line = NULL;
        /* Adjust counters */
        data += len + 1;
        processed_bytes += len + 1;
        file->parsed = 0;
        lines++;
    }
    file->parsed = file->buf_len;
    *bytes = processed_bytes;

    /* Append the temporal buffer to a dyntag, then release it */
    flb_input_dyntag_append_raw(ctx->i_ins,
                                file->tag_buf,
                                file->tag_len,
                                out_sbuf->data,
                                out_sbuf->size);
    msgpack_sbuffer_destroy(out_sbuf);
    return lines;
}

static inline void drop_bytes(char *buf, size_t len, int pos, int bytes)
{
    memmove(buf + pos,
            buf + pos + bytes,
            len - pos - bytes);
}

#ifdef FLB_HAVE_REGEX
static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    struct flb_hash *ht = data;
    char *p;

    while ((p = strchr((char *) value, '.'))) {
        *p = '_';
    }

    flb_hash_add(ht, (char *) name, strlen((char *) name), (char *) value, vlen);
}
#endif

#ifdef FLB_HAVE_REGEX
static int tag_compose(char *tag, struct flb_regex *tag_regex, char *fname, char **out_buf, size_t *out_size)
#else
static int tag_compose(char *tag, char *fname, char **out_buf, size_t *out_size)
#endif
{
    int i;
    int len;
    char *p;
    char *buf = *out_buf;
    size_t buf_s = 0;
#ifdef FLB_HAVE_REGEX
    ssize_t n;
    struct flb_regex_search result;
    struct flb_hash *ht;
    char *beg;
    char *end;
    int ret;
    char *tmp;
    size_t tmp_s;
#endif

#ifdef FLB_HAVE_REGEX
    if (tag_regex) {
        n = flb_regex_do(tag_regex, (unsigned char *) fname, strlen(fname), &result);
        if (n <= 0) {
            flb_error("[in_tail] invalid pattern for given file %s", fname);
            return -1;
        }
        else {
            ht = flb_hash_create(FLB_HASH_EVICT_NONE, FLB_HASH_TABLE_SIZE, FLB_HASH_TABLE_SIZE);
            flb_regex_parse(tag_regex, &result, cb_results, ht);

            for (p = tag, beg = p; (beg = strchr(p, '<')); p = end + 2) {
                if (beg != p) {
                    len = (beg - p);
                    memcpy(buf + buf_s, p, len);
                    buf_s += len;
                }

                beg++;

                end = strchr(beg, '>');
                if (end && !memchr(beg, '<', end - beg)) {
                    end--;

                    len = end - beg + 1;
                    ret = flb_hash_get(ht, beg, len, &tmp, &tmp_s);
                    if (ret != -1) {
                        memcpy(buf + buf_s, tmp, tmp_s);
                        buf_s += tmp_s;
                    }
                    else {
                        memcpy(buf + buf_s, "_", 1);
                        buf_s++;
                    }
                }
                else {
                    flb_error("[in_tail] missing closing angle bracket in tag %s at position %i", tag, beg - tag);
                    flb_hash_destroy(ht);
                    return -1;
                }
            }

            flb_hash_destroy(ht);

            if (*p) {
                len = strlen(p);
                memcpy(buf + buf_s, p, len);
                buf_s += len;
            }
        }
    }
    else {
#endif
        p = strchr(tag, '*');
        if (!p) {
            return -1;
        }

        /* Copy tag prefix if any */
        len = (p - tag);
        if (len > 0) {
            memcpy(buf, tag, len);
            buf_s += len;
        }

        /* Append file name */
        len = strlen(fname);
        memcpy(buf + buf_s, fname, len);
        buf_s += len;

        /* Tag suffix (if any) */
        p++;
        if (*p) {
            len = strlen(tag);
            memcpy(buf + buf_s, p, (len - (p - tag)));
            buf_s += (len - (p - tag));
        }

        /* Sanitize buffer */
        for (i = 0; i < buf_s; i++) {
            if (buf[i] == '/') {
                if (i > 0) {
                    buf[i] = '.';
                }
                else {
                    drop_bytes(buf, buf_s, i, 1);
                    buf_s--;
                    i--;
                }
            }

            if (buf[i] == '.' && i > 0) {
                if (buf[i - 1] == '.') {
                    drop_bytes(buf, buf_s, i, 1);
                    buf_s--;
                    i--;
                }
            }
            else if (buf[i] == '*') {
                    drop_bytes(buf, buf_s, i, 1);
                    buf_s--;
                    i--;
            }
        }

        /* Check for an ending '.' */
        if (buf[buf_s - 1] == '.') {
            drop_bytes(buf, buf_s, buf_s - 1, 1);
            buf_s--;
        }
#ifdef FLB_HAVE_REGEX
    }
#endif

    buf[buf_s] = '\0';
    *out_size = buf_s;

    return 0;
}

int flb_tail_file_exists(char *name, struct flb_tail_config *ctx)
{
    struct mk_list *head;
    struct flb_tail_file *file;

    /* Iterate static list */
    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (flb_tail_file_name_cmp(name, file) == 0) {
            return FLB_TRUE;
        }
    }

    /* Iterate dynamic list */
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (flb_tail_file_name_cmp(name, file) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int flb_tail_file_append(char *path, struct stat *st, int mode,
                         struct flb_tail_config *ctx)
{
    int fd;
    int ret;
    off_t offset;
    char *p;
    char out_tmp[PATH_MAX];
    size_t out_size;
    struct mk_list *head;
    struct flb_tail_file *file;

    if (!S_ISREG(st->st_mode)) {
        return -1;
    }

    /* Double check this file is not already being monitored */
    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (flb_tail_file_name_cmp(path, file) == 0) {
            return -1;
        }
    }
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (flb_tail_file_name_cmp(path, file) == 0) {
            return -1;
        }
    }

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        flb_errno();
        flb_error("[in_tail] could not open %s", path);
        return -1;
    }

    file = flb_calloc(1, sizeof(struct flb_tail_file));
    if (!file) {
        flb_errno();
        close(fd);
        return -1;
    }

    /* Initialize */
    file->watch_fd  = -1;
    file->fd        = fd;

    /*
     * Duplicate string into 'file' structure, the called function
     * take cares to resolve real-name of the file in case we are
     * running in a non-Linux system.
     *
     * Depending of the operating system, the way to obtain the file
     * name associated to it file descriptor can have different behaviors
     * specifically if it root path it's under a symbolic link. On Linux
     * we can trust the file name but in others it's better to solve it
     * with some extra calls.
     */
    ret = flb_tail_file_name_dup(path, file);
    if (!file->name) {
        flb_errno();
        close(fd);
        flb_free(file);
        return -1;
    }

    file->offset    = 0;
    file->inode     = st->st_ino;
    file->size      = st->st_size;
    file->buf_len   = 0;
    file->parsed    = 0;
    file->config    = ctx;
    file->tail_mode = mode;
    file->tag_len   = 0;
    file->tag_buf   = NULL;
    file->rotated   = 0;
    file->pending_bytes = 0;
    file->mult_firstline = FLB_FALSE;
    file->mult_keys = 0;
    file->mult_flush_timeout = 0;
    file->mult_skipping = FLB_FALSE;
    msgpack_sbuffer_init(&file->mult_sbuf);
    file->dmode_flush_timeout = 0;
    file->dmode_buf = flb_sds_create_size(ctx->docker_mode == FLB_TRUE ? 65536 : 0);
    file->dmode_lastline = flb_sds_create_size(ctx->docker_mode == FLB_TRUE ? 20000 : 0);
    file->db_id     = 0;
    file->skip_next = FLB_FALSE;
    file->skip_warn = FLB_FALSE;

    /* Local buffer */
    file->buf_size = ctx->buf_chunk_size;
    file->buf_data = flb_malloc(file->buf_size);
    if (!file->buf_data) {
        flb_errno();
        close(fd);
        flb_free(file->name);
        flb_free(file);
        return -1;
    }

    /* Initialize (optional) dynamic tag */
    if (ctx->dynamic_tag == FLB_TRUE) {
        p = out_tmp;
#ifdef FLB_HAVE_REGEX
        ret = tag_compose(ctx->i_ins->tag, ctx->tag_regex, basename(path), &p, &out_size);
#else
        ret = tag_compose(ctx->i_ins->tag, path, &p, &out_size);
#endif
        if (ret == 0) {
            file->tag_len = out_size;
            file->tag_buf = flb_strdup(p);
        }
    }
    else {
        file->tag_len = strlen(ctx->i_ins->tag);
        file->tag_buf = flb_strdup(ctx->i_ins->tag);
    }

    /* Register this file into the fs_event monitoring */
    ret = flb_tail_fs_add(file);
    if (ret == -1) {
        flb_error("[in_tail] could not register file into fs_events");
        flb_free(file->name);
        flb_free(file);
        return -1;
    }

    if (mode == FLB_TAIL_STATIC) {
        mk_list_add(&file->_head, &ctx->files_static);
    }
    else if (mode == FLB_TAIL_EVENT) {
        mk_list_add(&file->_head, &ctx->files_event);
    }

    /*
     * Register or update the file entry, likely if the entry already exists
     * into the database, the offset may be updated.
     */
    if (ctx->db) {
        flb_tail_db_file_set(file, ctx);
    }

    /* Seek if required */
    if (file->offset > 0) {
        offset = lseek(file->fd, file->offset, SEEK_SET);
        if (offset == -1) {
            flb_errno();
            flb_tail_file_remove(file);
            return -1;
        }
    }

    flb_debug("[in_tail] add to scan queue %s, offset=%lu", path, file->offset);
    return 0;
}

void flb_tail_file_remove(struct flb_tail_file *file)
{
    if (file->rotated > 0) {
        mk_list_del(&file->_rotate_head);
    }

    flb_sds_destroy(file->dmode_buf);
    flb_sds_destroy(file->dmode_lastline);
    mk_list_del(&file->_head);
    flb_tail_fs_remove(file);
    close(file->fd);
    if (file->tag_buf) {
        flb_free(file->tag_buf);
    }

    flb_free(file->buf_data);
    flb_free(file->name);
#if !defined(__linux__)
    flb_free(file->real_name);
#endif
    flb_free(file);
}

int flb_tail_file_remove_all(struct flb_tail_config *ctx)
{
    int count = 0;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_tail_file *file;

    mk_list_foreach_safe(head, tmp, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        flb_tail_file_remove(file);
        count++;
    }

    mk_list_foreach_safe(head, tmp, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        flb_tail_file_remove(file);
        count++;
    }

    return count;
}

int flb_tail_file_chunk(struct flb_tail_file *file)
{
    int ret;
    char *tmp;
    size_t size;
    off_t capacity;
    off_t processed_bytes;
    ssize_t bytes;
    struct flb_tail_config *ctx;

    /* Check if we the engine issued a pause */
    ctx = file->config;
    if (flb_input_buf_paused(ctx->i_ins) == FLB_TRUE) {
        return FLB_TAIL_BUSY;
    }

    capacity = (file->buf_size - file->buf_len) - 1;
    if (capacity < 1) {
        /*
         * If there is no more room for more data, try to increase the
         * buffer under the limit of buffer_max_size.
         */
        if (file->buf_size >= ctx->buf_max_size) {
            if (ctx->skip_long_lines == FLB_FALSE) {
                flb_error("[in_tail] file=%s requires a larger buffer size, "
                          "lines are too long. Skipping file.", file->name);
                return FLB_TAIL_ERROR;
            }

            /* Warn the user */
            if (file->skip_warn == FLB_FALSE) {
                flb_warn("[in_tail] file=%s have long lines. "
                         "Skipping long lines.", file->name);
                file->skip_warn = FLB_TRUE;
            }

            /* Do buffer adjustments */
            file->buf_len = 0;
            file->skip_next = FLB_TRUE;
        }
        else {
            size = file->buf_size + ctx->buf_chunk_size;
            if (size > ctx->buf_max_size) {
                size = ctx->buf_max_size;
            }

            /* Increase the buffer size */
            tmp = flb_realloc(file->buf_data, size);
            if (tmp) {
                flb_trace("[in_tail] file=%s increase buffer size %lu => %lu bytes",
                          file->name, file->buf_size, size);
                file->buf_data = tmp;
                file->buf_size = size;
            }
            else {
                flb_errno();
                flb_error("[in_tail] cannot increase buffer size for %s, "
                          "skipping file.", file->name);
                return FLB_TAIL_ERROR;
            }
        }
        capacity = (file->buf_size - file->buf_len) - 1;
    }

    bytes = read(file->fd, file->buf_data + file->buf_len, capacity);
    if (bytes > 0) {
        /* we read some data, let the content processor take care of it */
        file->buf_len += bytes;
        file->buf_data[file->buf_len] = '\0';

        /* Now that we have some data in the buffer, call the data processor
         * which aims to cut lines and register the entries into the engine.
         *
         * The returned value is the absolute offset the file must be seek
         * now. It may need to get back a few bytes at the beginning of a new
         * line.
         */
        ret = process_content(file, &processed_bytes);
        if (ret >= 0) {
            flb_debug("[in_tail] file=%s read=%lu lines=%i",
                      file->name, bytes, ret);
        }
        else {
            flb_debug("[in_tail] file=%s ERROR", file->name);
            return FLB_TAIL_ERROR;
        }


        /* Adjust the file offset and buffer */
        file->offset += processed_bytes;
        consume_bytes(file->buf_data, processed_bytes, file->buf_len);
        file->buf_len -= processed_bytes;
        file->buf_data[file->buf_len] = '\0';

        if (file->config->db) {
            flb_tail_db_file_offset(file, file->config);
        }

        /* Data was consumed but likely some bytes still remain */
        return FLB_TAIL_OK;
    }
    else if (bytes == 0) {
        /* We reached the end of file, let's wait for some incoming data */
        return FLB_TAIL_WAIT;
    }
    else {
        /* error */
        flb_errno();
        flb_error("[in_tail] error reading %s", file->name);
        return FLB_TAIL_ERROR;
    }

    return FLB_TAIL_ERROR;
}

int flb_tail_file_to_event(struct flb_tail_file *file)
{
    int ret;
    char *name;
    struct stat st;
    struct stat st_rotated;

    /* Check if the file promoted have pending bytes */
    ret = fstat(file->fd, &st);
    if (ret != 0) {
        return -1;
    }

    if (file->offset < st.st_size) {
        file->pending_bytes = (st.st_size - file->offset);
        tail_signal_pending(file->config);
    }
    else {
        file->pending_bytes = 0;
    }

    /* Check if this file have been rotated */
    name = flb_tail_file_name(file);
    if (!name) {
        flb_debug("[in_tail] cannot detect if file was rotated: %s",
                  file->name);
        return -1;
    }

    if (flb_tail_file_name_cmp(name, file) != 0) {
        ret = stat(name, &st_rotated);
        if (ret == -1) {
            flb_free(name);
            return -1;
        }
        else if (st_rotated.st_ino != st.st_ino) {
            flb_trace("[in_tail] static file rotated: %s => to %s",
                      file->name, name);
            flb_tail_file_rotated(file);
        }
    }
    flb_free(name);

    /* Notify the fs-event handler that we will start monitoring this 'file' */
    ret = flb_tail_fs_add(file);
    if (ret == -1) {
        return -1;
    }

    /* List change */
    mk_list_del(&file->_head);
    mk_list_add(&file->_head, &file->config->files_event);
    file->tail_mode = FLB_TAIL_EVENT;

    return 0;
}

/*
 * Given an open file descriptor, return the filename. This function is a
 * bit slow and it aims to be used only when a file is rotated.
 */
char *flb_tail_file_name(struct flb_tail_file *file)
{
    int ret;
    char *buf;
#ifdef __linux__
    ssize_t s;
    char tmp[128];
#elif defined(__APPLE__)
    char path[PATH_MAX];
#endif

    buf = flb_malloc(PATH_MAX);
    if (!buf) {
        flb_errno();
        return NULL;
    }

#ifdef __linux__
    ret = snprintf(tmp, sizeof(tmp) - 1, "/proc/%i/fd/%i", getpid(), file->fd);
    if (ret == -1) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    s = readlink(tmp, buf, PATH_MAX);
    if (s == -1) {
        flb_free(buf);
        flb_errno();
        return NULL;
    }
    buf[s] = '\0';

#elif __APPLE__
    int len;

    ret = fcntl(file->fd, F_GETPATH, path);
    if (ret == -1) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }

    len = strlen(path);
    memcpy(buf, path, len);
    buf[len] = '\0';
#endif

    return buf;
}

int flb_tail_file_name_dup(char *path, struct flb_tail_file *file)
{
    file->name = flb_strdup(path);
    if (!file->name) {
        flb_errno();
        return -1;
    }
    file->name_len = strlen(file->name);

#if !defined(__linux__)
    if (file->real_name) {
        flb_free(file->real_name);
    }
    file->real_name = flb_tail_file_name(file);
    if (!file->real_name) {
        flb_errno();
        flb_free(file->name);
        file->name = NULL;
        return -1;
    }
#endif

    return 0;
}

/* Invoked every time a file was rotated */
int flb_tail_file_rotated(struct flb_tail_file *file)
{
    int ret;
    int create = FLB_FALSE;
    char *name;
    char *tmp;
    struct stat st;
    struct flb_tail_config *ctx = file->config;

    /* Get stats from the original file name (if a new one exists) */
    ret = stat(file->name, &st);
    if (ret == 0) {
        /* Check if we need to re-create an entry with the original name */
        if (st.st_ino != file->inode && file->rotated == 0) {
            create = FLB_TRUE;
        }
    }

    /* Get the new file name */
    name = flb_tail_file_name(file);
    if (!name) {
        return -1;
    }

    flb_debug("[in_tail] rotated: %s -> %s",
              file->name, name);

    /* Rotate the file in the database */
    if (file->config->db) {
        ret = flb_tail_db_file_rotate(name, file, file->config);
        if (ret == -1) {
            flb_error("[in_tail] could not rotate file %s->%s in database",
                      file->name, name);
        }
    }

    /* Update local file entry */
    tmp        = file->name;
    flb_tail_file_name_dup(name, file);

    if (file->rotated == 0) {
        file->rotated = time(NULL);
        mk_list_add(&file->_rotate_head, &file->config->files_rotated);
    }

    /* Request to append 'new' file created */
    if (create == FLB_TRUE) {
        flb_tail_scan(ctx->path, ctx);
        tail_signal_manager(file->config);
    }
    flb_free(tmp);
    flb_free(name);

    return 0;
}

int flb_tail_file_rotated_purge(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *context)
{
    int count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_file *file;
    struct flb_tail_config *ctx = context;
    time_t now;

    now = time(NULL);
    mk_list_foreach_safe(head, tmp, &ctx->files_rotated) {
        file = mk_list_entry(head, struct flb_tail_file, _rotate_head);
        if ((file->rotated + ctx->rotate_wait) <= now) {
            flb_debug("[in_tail] purge rotated file %s", file->name);
            if (file->pending_bytes > 0 && flb_input_buf_paused(i_ins)) {
                flb_warn("[in_tail] purged rotated file while data ingestion is paused, consider increasing rotate_wait");
            }
            flb_tail_file_remove(file);
            count++;
        }
    }

    return count;
}
