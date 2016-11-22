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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <fluent-bit/flb_input.h>

#include "tail.h"
#include "tail_file.h"
#include "tail_config.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_line(time_t time, char *line,
                            int line_len, struct flb_tail_file *file)
{
    struct flb_tail_config *ctx = file->config;

    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time);

    msgpack_pack_map(&ctx->mp_pck, 1);
    msgpack_pack_bin(&ctx->mp_pck, 3);
    msgpack_pack_bin_body(&ctx->mp_pck, "log", 3);
    msgpack_pack_bin(&ctx->mp_pck, line_len);
    msgpack_pack_bin_body(&ctx->mp_pck, line, line_len);

    return 0;
}

static int process_content(struct flb_tail_file *file, off_t *offset)
{
    int len;
    int lines = 0;
    char *p;
    time_t t = time(NULL);

    while ((p = strchr(file->buf_data + file->parsed, '\n'))) {
        len = (p - file->buf_data);
        if (len == 0) {
            consume_bytes(file->buf_data, 1, file->buf_len);
            file->buf_len--;
            file->parsed = 0;
            file->buf_data[file->buf_len] = '\0';
            continue;
        }

        pack_line(t, file->buf_data, len, file);

        /*
         * FIXME: here we are moving bytes to the left on each iteration, it
         * would be fast if we do this after this while(){}
         */
        consume_bytes(file->buf_data, len + 1, file->buf_len);
        file->buf_len -= len + 1;
        file->buf_data[file->buf_len] = '\0';
        file->parsed = 0;
        lines++;
    }
    file->parsed = file->buf_len;
    return lines;
}

int flb_tail_file_append(char *path, struct stat *st,
                         int mode,
                         struct flb_tail_config *config)
{
    int fd;
    struct flb_tail_file *file;

    if (!S_ISREG(st->st_mode)) {
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        flb_errno();
        flb_error("[in_tail] could not open %s", path);
        return -1;
    }

    file = flb_malloc(sizeof(struct flb_tail_file));
    if (!file) {
        flb_errno();
        return -1;
    }

    file->watch_fd  = 0;
    file->fd        = fd;
    file->name      = flb_strdup(path);
    file->offset    = 0;
    file->size      = st->st_size;
    file->buf_len   = 0;
    file->parsed    = 0;
    file->config    = config;
    file->tail_mode = mode;

    if (mode == FLB_TAIL_STATIC) {
        mk_list_add(&file->_head, &config->files_static);
    }
    else if (mode == FLB_TAIL_EVENT) {
        mk_list_add(&file->_head, &config->files_event);
    }

    flb_debug("[in_tail] add to scan queue %s", path);
    return 0;
}

void flb_tail_file_remove(struct flb_tail_file *file)
{
    mk_list_del(&file->_head);
    if (file->tail_mode == FLB_TAIL_EVENT) {
        flb_tail_fs_remove(file);
    }
    close(file->fd);
    flb_free(file->name);
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
    off_t capacity;
    off_t offset;
    ssize_t bytes;

    /* Seek if required */
    if (file->offset > 0) {
        offset = lseek(file->fd, file->offset, SEEK_SET);
        if (offset == -1) {
            perror("lseek");
            flb_errno();
            return -1;
        }
    }

    capacity = sizeof(file->buf_data) - file->buf_len - 1;
    if (capacity < 1) {
        /* we expect at least a log line have a length less than 32KB */
        return -1;
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
        ret = process_content(file, &offset);
        if (ret >= 0) {
            flb_debug("[in_tail] file=%s read=%lu lines=%i",
                      file->name, bytes, ret);
        }
        else {
            flb_debug("[in_tail] file=%s ERROR", file->name);
            return FLB_TAIL_ERROR;
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
