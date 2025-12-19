/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_log_event_encoder.h>

#ifdef FLB_HAVE_PARSER
#include <fluent-bit/multiline/flb_ml.h>
#endif

#include "tail.h"
#include "tail_config.h"

struct flb_tail_file {
    /* Inotify */
    int watch_fd;
    /* file lookup info */
    int fd;
    int64_t size;
    int64_t offset;             /* this represents the raw file offset, not
                                   the input data offset (see stream_offset) */
    int64_t anchor_offset;      /* compressed: file offset at member start */
    uint64_t skip_bytes;        /* compressed: decompressed bytes to skip */
    uint64_t exclude_bytes;     /* compressed: runtime countdown during skip */
    int skipping_mode;          /* compressed: skipping previously read data */
    int64_t last_line;
    uint64_t  dev_id;
    uint64_t  inode;
    uint64_t  link_inode;
    int   is_link;
    char *name;                 /* target file name given by scan routine */
    char *real_name;            /* real file name in the file system */
    char *orig_name;            /* original file name (before rotation) */
    size_t name_len;
    size_t orig_name_len;
    time_t rotated;
    int64_t pending_bytes;
    size_t stream_offset;       /* this represents the logical data offset
                                   which for compressed files could be higher
                                   than the file size or offset */

    /* dynamic tag for this file */
    int tag_len;
    char *tag_buf;

    /* OLD multiline */
    time_t mult_flush_timeout;  /* time when multiline started           */
    int mult_firstline;         /* bool: mult firstline found ?          */
    int mult_firstline_append;  /* bool: mult firstline appendable ?     */
    int mult_skipping;          /* skipping because ignode_older than ?  */
    int mult_keys;              /* total number of buffered keys         */

    int mult_records;           /* multiline records counter mult_sbuf   */
    msgpack_sbuffer mult_sbuf;  /* temporary msgpack buffer              */
    msgpack_packer mult_pck;    /* temporary msgpack packer              */
    struct flb_time mult_time;  /* multiline time parsed from first line */

    /* OLD docker mode */
    time_t dmode_flush_timeout; /* time when docker mode started         */
    flb_sds_t dmode_buf;        /* buffer for docker mode                */
    flb_sds_t dmode_lastline;   /* last incomplete line                  */
    bool dmode_complete;        /* buffer contains completed log         */
    bool dmode_firstline;       /* dmode mult firstline found ?          */

    /* multiline engine: file stream_id and local buffers */
    uint64_t ml_stream_id;

    /* content parsing, positions and buffer */
    size_t parsed;
    size_t buf_len;
    size_t buf_size;
    char *buf_data;

    struct flb_decompression_context *decompression_context;

    /*
     * This value represent the number of bytes procesed by process_content()
     * in the last iteration.
     */
    size_t last_processed_bytes;

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

    uint64_t hash_bits;
    flb_sds_t hash_key;

    /* There are dedicated log event encoders for
     * single and multi line events because I am respecting
     * the old behavior which resulted in grouping both types
     * of logs in tail_file.c but I don't know if this is
     * strictly necessary.
     */
    struct flb_log_event_encoder *ml_log_event_encoder;
    struct flb_log_event_encoder *sl_log_event_encoder;

    /* reference */
    int tail_mode;
    struct flb_tail_config *config;
    struct mk_list _head;
    struct mk_list _rotate_head;
};
#endif
