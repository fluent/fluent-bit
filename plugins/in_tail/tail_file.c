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

#include <fluent-bit/flb_input.h>
#include "tail_config.h"
#include "tail_file.h"

static int process_content(struct flb_tail_file *file, off_t *offset)
{
    int len;
    int lines = 0;
    char *p;
    off_t off = 0;

    while ((p = strchr(file->buf_data + off, '\n'))) {
        char *b = flb_malloc(32128);
        memset(b, '\0', 32128);

        len = (p - (file->buf_data + off));
        strncpy(b, file->buf_data + off, len);
        b[len] = '\0';
        off += len + 1;
        printf("=>%s\n", b);
        flb_free(b);

        lines++;
    }

    *offset = off;
    return lines;
}

int flb_tail_file_append(char *path, struct stat *st,
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

    file->fd      = fd;
    file->name    = flb_strdup(path);
    file->offset  = 0;
    file->size    = st->st_size;
    file->buf_len = 0;
    mk_list_add(&file->_head, &config->files);

    flb_debug("[in_tail] add to scan queue %s", path);
    return 0;
}

void flb_tail_file_remove(struct flb_tail_file *file)
{
    mk_list_del(&file->_head);
    close(file->fd);
    flb_free(file->name);
    flb_free(file);
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
        if (offset < 0) {
            flb_errno();
            return -1;
        }
    }

    capacity = sizeof(file->buf_data) - file->buf_len;
    if (capacity < 1) {
        /* we expect at least a log line have a length less than 32KB */
        return -1;
    }

    bytes = read(file->fd, file->buf_data + file->buf_len, capacity);
    if (bytes > 0) {
        /* we read some data, let the content processor take care of it */
        file->buf_data[file->buf_len + bytes] = '\0';

        /* Now that we have some data in the buffer, call the data processor
         * which aims to cut lines and register the entries into the engine.
         *
         * The returned value is the absolute offset the file must be seek
         * now. It may need to get back a few bytes at the beginning of a new
         * line.
         */
        ret = process_content(file, &offset);
        if (ret == -1) {
            return -1;
        }

        file->offset = offset;
        if (file->offset >= file->size) {
            /* FIXME */
        }

        return 0;
    }
    else if (bytes == 0) {
        /* FIXME: we reached the end of file, let's wait for inotify */
        return -1;
    }
    else {
        /* error */
        flb_errno();
        flb_error("[in_tail] error reading %s", file->name);
        return -1;
    }

    return 0;
}
