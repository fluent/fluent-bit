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

#ifndef FLB_OUT_MANTICORE_H
#define FLB_OUT_MANTICORE_H

#include <fluent-bit/flb_sds.h>

#include <stdint.h>
#include <stdio.h>

#define FLB_MANTICORE_DEFAULT_PORT 9308
#define FLB_MANTICORE_BULK_URI     "/bulk?bulk_import="

struct flb_out_manticore {
    char *table;
    char *action;
    const char *bulk_action;
    char *id_key;
    char *http_user;
    char *http_passwd;
    int single_chunk;
    int session_failed;
    char *spool_path;
    flb_sds_t commit_path;
    FILE *spool;
    int spool_fd;
    FILE *commit;
    int commit_fd;
    uint64_t *session_ids;
    size_t session_id_count;
    size_t session_id_capacity;
    size_t max_session_ids;
    flb_sds_t table_json;
    flb_sds_t bulk_uri;
    size_t stream_chunk_size;
    size_t buffer_size;
    struct flb_upstream *u;
    struct flb_output_instance *ins;
    struct flb_config *config;
};

#endif
