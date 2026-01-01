/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_SYSTEMD_CONFIG_H
#define FLB_SYSTEMD_CONFIG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <systemd/sd-journal.h>

/* return values */
#define FLB_SYSTEMD_ERROR   -1 /* Systemd journal file read error. */
#define FLB_SYSTEMD_NONE     0
#define FLB_SYSTEMD_OK       1
#define FLB_SYSTEMD_MORE     2
#define FLB_SYSTEMD_BUSY     3

/* constants */
#define FLB_SYSTEMD_UNIT     "_SYSTEMD_UNIT"
#define FLB_SYSTEMD_UNKNOWN  "unknown"
#define FLB_SYSTEMD_MAX_FIELDS   "8000"
#define FLB_SYSTEMD_MAX_ENTRIES  "5000"

/* Input configuration & context */
struct flb_systemd_config {
    /* Journal */
    int fd;              /* Journal file descriptor */
    sd_journal *j;       /* Journal context */
    char *cursor;
    flb_sds_t path;
    flb_sds_t filter_type; /* sysytemd filter type: and|or */
    struct mk_list *systemd_filters;
    int pending_records;
    int read_from_tail;  /* read_from_tail option */
    int lowercase;
    int strip_underscores;

    /* Internal */
    int ch_manager[2];         /* pipe: channel manager    */
    int coll_fd_archive;       /* archive collector        */
    int coll_fd_journal;       /* journal, events mode     */
    int coll_fd_pending;       /* pending records          */
    int dynamic_tag;
    int max_fields;            /* max number of fields per record */
    int max_entries;           /* max number of records per iteration */
    size_t threshold;         /* threshold for retriveing journal */

#ifdef FLB_HAVE_SQLDB
    flb_sds_t db_path;
    struct flb_sqldb *db;
    flb_sds_t db_sync_mode;
    int db_sync;
    sqlite3_stmt *stmt_cursor;
#endif
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

struct flb_systemd_config *flb_systemd_config_create(struct flb_input_instance *i_ins,
                                                     struct flb_config *config);

int flb_systemd_config_destroy(struct flb_systemd_config *ctx);
#endif
