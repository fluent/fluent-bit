/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_IN_GELF_CONN_H
#define FLB_IN_GELF_CONN_H

#define FLB_GELF_TCP   1
#define FLB_GELF_UDP   2

#define FLB_GELF_CHUNK        65536
#define FLB_GELF_MAX_CHUNKS   128
#define FLB_GELF_TBL_SIZE     64

#define FLB_GELF_CHUNK_TMOUT  5

#define FLB_GELF_TYPE_UNSUPPORTED    0
#define FLB_GELF_TYPE_ZLIB           1
#define FLB_GELF_TYPE_GZIP           2
#define FLB_GELF_TYPE_CHUNKED        3
#define FLB_GELF_TYPE_UNCOMPRESSED   4

#define FLB_GELF_HEADER_ID     2
#define FLB_GELF_HEADER_SEQNUM 10
#define FLB_GELF_HEADER_SEQCNT 11
#define FLB_GELF_HEADER_SIZE   12

struct gelf_chunk_sgmt {
    void  *base;
    size_t len;
};

struct gelf_chunk {
    time_t start;
    size_t sgmt_found;
    size_t sgmt_cnt;
    struct gelf_chunk_sgmt sgmt[];
};

struct gelf_chunk_entry {
    uint64_t hash;
    uint64_t dib;
    uint64_t msg_id;
    struct gelf_chunk *chunk;
};

struct gelf_chunk_tbl {
    size_t size;
    size_t used;
    size_t resize_hits;
    struct gelf_chunk_entry *entries;
};

/* Context / Config*/
struct flb_gelf {
    /* Listening mode: tcp or udp */
    int mode;

    /* Network mode */
    char *listen;
    char port[24];

    /* strict parsing messages */
    bool strict;

    /* UDP/TCP */
    int server_fd;
    
    /* UDP buffer, data length and buffer size */
    char *buffer_data;
    size_t buffer_len;
    size_t buffer_size;

    struct gelf_chunk_tbl chunks;

    /* Buffers setup */
    size_t buffer_max_size;
    size_t buffer_chunk_size;

    /* List for connections and event loop */
    struct mk_list connections;
    struct mk_event_loop *evl;
    struct flb_input_instance *ins;
};

struct gelf_tcp_conn {
    struct mk_event event;           /* Built-in event data for mk_events */
    int fd;                          /* Socket file descriptor            */
    int status;                      /* Connection status                 */

    /* Buffer */
    char *buf_data;                  /* Buffer data                       */
    size_t buf_size;                 /* Buffer size                       */
    size_t buf_len;                  /* Buffer length                     */
    size_t buf_parsed;               /* Parsed buffer (offset)            */
    struct flb_input_instance *ins;  /* Parent plugin instance            */
    struct flb_gelf *ctx;            /* Plugin configuration context      */

    struct mk_list _head;
};

#endif
