/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_TAIL_INTERNAL_H
#define FLB_TAIL_INTERNAL_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include "tail.h"
#include "tail_config.h"

struct flb_tail_file {
    /* Inotify */
    int watch_fd;
    /* file lookup info */
    int fd;
    int64_t size;
    int64_t offset;
    int64_t last_line;
    uint64_t  inode;
    uint64_t  link_inode;
    int   is_link;
    char *name;                 /* target file name given by scan routine */
    char *real_name;            /* real file name in the file system */
    size_t name_len;
    time_t rotated;
    int64_t pending_bytes;

    /* dynamic tag for this file */
    int tag_len;
    char *tag_buf;

    /* multiline status */
    time_t mult_flush_timeout;  /* time when multiline started           */
    int mult_firstline;         /* bool: mult firstline found ?          */
    int mult_firstline_append;  /* bool: mult firstline appendable ?     */
    int mult_skipping;          /* skipping because ignode_older than ?  */
    int mult_keys;              /* total number of buffered keys         */
    msgpack_sbuffer mult_sbuf;  /* temporary msgpack buffer               */
    msgpack_packer mult_pck;    /* temporary msgpack packer               */
    struct flb_time mult_time;  /* multiline time parsed from first line */

    /* docker mode */
    time_t dmode_flush_timeout; /* time when docker mode started         */
    flb_sds_t dmode_buf;        /* buffer for docker mode                */
    flb_sds_t dmode_lastline;   /* last incomplete line                  */
    bool dmode_complete;        /* buffer contains completed log         */
    bool dmode_firstline;       /* dmode mult firstline found ?          */

    /* buffering */
    size_t parsed;
    size_t buf_len;
    size_t buf_size;
    char *buf_data;

    /*
     * Long-lines handling: this flag is enabled when a previous line was
     * too long and the buffer did not contain a \n, so when reaching the
     * missing \n, skip that content and move forward.
     *
     * This flag is only set when Skip_Long_Lines is On.
     */
    int skip_next;

    /* Did the plugin already warn the user about long lines ? */
    int skip_warn;

    /* Opaque data type for specific fs-event backend data */
    void *fs_backend;

    /* database reference */
    uint64_t db_id;

    /* reference */
    int tail_mode;
    struct flb_tail_config *config;
    struct mk_list _head;
    struct mk_list _rotate_head;
};
#endif
