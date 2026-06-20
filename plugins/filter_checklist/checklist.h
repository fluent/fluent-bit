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

#ifndef FLB_FILTER_CHECK_H
#define FLB_FILTER_CHECK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sqldb.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_record_accessor.h>

#define LINE_SIZE   2048
#define CHECK_HASH_TABLE_SIZE 100000
#define CHECK_EXACT_MATCH     0  /* exact string match */
#define CHECK_PARTIAL_MATCH   1  /* partial match */

/* plugin context */
struct checklist {
    /* config options */
    int mode;
    int ignore_case;
    int print_query_time;
    flb_sds_t file;
    flb_sds_t lookup_key;
    struct mk_list *records;

    /* internal */
    struct flb_sqldb *db;
    sqlite3_stmt *stmt_insert;
    sqlite3_stmt *stmt_check;
    struct flb_hash_table *ht;
    struct flb_record_accessor *ra_lookup_key;
    struct flb_filter_instance *ins;
    struct flb_config *config;
};

/* create table */
#define SQL_CREATE_TABLE                                                \
    "CREATE TABLE IF NOT EXISTS list ("                                 \
    "  pattern text "                                                   \
    ");"

#define SQL_CASE_SENSITIVE                                              \
    "PRAGMA case_sensitive_like = true;"

/* insert pattern into list table */
#define SQL_INSERT   "INSERT INTO list (pattern) VALUES (@val);"

/* validate incoming value against list */
#define SQL_CHECK                                                       \
    "SELECT pattern FROM list WHERE @val LIKE (pattern || '%');"

#endif
