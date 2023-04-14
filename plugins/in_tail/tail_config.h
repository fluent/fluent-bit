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

#ifndef FLB_TAIL_CONFIG_H
#define FLB_TAIL_CONFIG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_log_event.h>
#ifdef FLB_HAVE_REGEX
#include <fluent-bit/flb_regex.h>
#endif
#ifdef FLB_HAVE_PARSER
#include <fluent-bit/multiline/flb_ml.h>
#endif

#include <xxhash.h>

/* Metrics */
#ifdef FLB_HAVE_METRICS
#define FLB_TAIL_METRIC_F_OPENED  100  /* number of opened files  */
#define FLB_TAIL_METRIC_F_CLOSED  101  /* number of closed files  */
#define FLB_TAIL_METRIC_F_ROTATED 102  /* number of rotated files */
#endif

struct flb_tail_config {
    int fd_notify;             /* inotify fd               */
    flb_pipefd_t ch_manager[2];    /* pipe: channel manager    */
    flb_pipefd_t ch_pending[2];    /* pipe: pending events     */
    int ch_reads;              /* count number if signal reads */
    int ch_writes;             /* count number of signal writes */

    /* Buffer Config */
    size_t buf_chunk_size;     /* allocation chunks        */
    size_t buf_max_size;       /* max size of a buffer     */

    /* Static files processor */
    size_t static_batch_size;

    /* Event files processor */
    size_t event_batch_size;

    /* Collectors */
    int coll_fd_static;
    int coll_fd_scan;
    int coll_fd_watcher;
    int coll_fd_rotated;
    int coll_fd_pending;
    int coll_fd_inactive;
    int coll_fd_dmode_flush;
    int coll_fd_mult_flush;
    int coll_fd_progress_check;

    /* Backend collectors */
    int coll_fd_fs1;           /* used by fs_inotify & fs_stat */
    int coll_fd_fs2;           /* only used by fs_stat         */

    /* Configuration */
    int dynamic_tag;           /* dynamic tag ? e.g: abc.*     */
#ifdef FLB_HAVE_REGEX
    struct flb_regex *tag_regex;/* path to tag regex           */
#endif
    int refresh_interval_sec;  /* seconds to re-scan           */
    long refresh_interval_nsec;/* nanoseconds to re-scan       */
    int read_from_head;        /* read new files from head     */
    int rotate_wait;           /* sec to wait on rotated files */
    int watcher_interval;      /* watcher interval             */
    int ignore_older;          /* ignore fields older than X seconds        */
    time_t last_pending;       /* last time a 'pending signal' was emitted' */
    struct mk_list *path_list; /* list of paths to scan (glob) */
    flb_sds_t path_key;        /* key name of file path        */
    flb_sds_t key;             /* key for unstructured record  */
    int   skip_long_lines;     /* skip long lines              */
    int   skip_empty_lines;    /* skip empty lines (off)       */
    int   exit_on_eof;         /* exit fluent-bit on EOF, test */

    int progress_check_interval;      /* watcher interval             */
    int progress_check_interval_nsec; /* watcher interval             */

#ifdef FLB_HAVE_INOTIFY
    int   inotify_watcher;     /* enable/disable inotify monitor */
#endif
    flb_sds_t offset_key;      /* key name of file offset      */

    /* Database */
#ifdef FLB_HAVE_SQLDB
    struct flb_sqldb *db;
    int db_sync;
    int db_locking;
    flb_sds_t db_journal_mode;
    sqlite3_stmt *stmt_get_file;
    sqlite3_stmt *stmt_insert_file;
    sqlite3_stmt *stmt_delete_file;
    sqlite3_stmt *stmt_rotate_file;
    sqlite3_stmt *stmt_offset;
#endif

    /* Parser / Format */
    struct flb_parser *parser;

    /* Multiline */
    int multiline;             /* multiline enabled ?  */
    int multiline_flush;       /* multiline flush/wait */
    struct flb_parser *mult_parser_firstline;
    struct mk_list mult_parsers;

    /* Docker mode */
    int docker_mode;           /* Docker mode enabled ?  */
    int docker_mode_flush;     /* Docker mode flush/wait */
    struct flb_parser *docker_mode_parser; /* Parser for separate multiline logs */

    /* Multiline core engine */
    struct flb_ml *ml_ctx;
    struct mk_list *multiline_parsers;

    uint64_t files_static_count;   /* number of items in the static file list */
    struct mk_list files_static;
    struct mk_list files_event;

    /* List of rotated files that needs to be removed after 'rotate_wait' */
    struct mk_list files_rotated;

    /* List of shell patterns used to exclude certain file names */
    struct mk_list *exclude_list;

    /* Plugin input instance */
    struct flb_input_instance *ins;

    struct flb_log_event_encoder log_event_encoder;
    struct flb_log_event_decoder log_event_decoder;

    /* Metrics */
    struct cmt_counter *cmt_files_opened;
    struct cmt_counter *cmt_files_closed;
    struct cmt_counter *cmt_files_rotated;

    /* Hash: hash tables for quick acess to registered files */
    struct flb_hash_table *static_hash;
    struct flb_hash_table *event_hash;

    struct flb_config *config;
};

struct flb_tail_config *flb_tail_config_create(struct flb_input_instance *ins,
                                               struct flb_config *config);
int flb_tail_config_destroy(struct flb_tail_config *config);

#endif
