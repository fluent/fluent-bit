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

#ifndef FLB_OUT_PGSQL_H
#define FLB_OUT_PGSQL_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_output_plugin.h>

#include <libpq-fe.h>

#define FLB_PGSQL_HOST "127.0.0.1"
#define FLB_PGSQL_PORT 5432
#define FLB_PGSQL_DBNAME "fluentbit"
#define FLB_PGSQL_TABLE "fluentbit"
#define FLB_PGSQL_TIMESTAMP_KEY "date"
#define FLB_PGSQL_POOL_SIZE 4
#define FLB_PGSQL_MIN_POOL_SIZE 1
#define FLB_PGSQL_SYNC FLB_FALSE
#define FLB_PGSQL_COCKROACH FLB_FALSE

#define FLB_PGSQL_INSERT "INSERT INTO %s (tag, time, data) SELECT %s, "   \
    "to_timestamp(CAST(value->>'%s' as FLOAT)),"        \
    " * FROM json_array_elements(%s);"
#define FLB_PGSQL_INSERT_COCKROACH "INSERT INTO %s (tag, time, data) SELECT %s,"  \
    "CAST(value->>'%s' AS INTERVAL) + DATE'1970-01-01',"        \
    " * FROM json_array_elements(%s);"

struct flb_pgsql_conn {
    struct mk_list _head;
    PGconn *conn;
    int number;
};

struct flb_pgsql_config {

    /* database */
    char *db_hostname;
    char db_port[8];
    const char *db_name;
    flb_sds_t db_table;

    /* auth */
    const char *db_user;
    const char *db_passwd;

    /* time key */
    flb_sds_t timestamp_key;

    /* instance reference */
    struct flb_output_instance *ins;

    /* connections options */
    const char *conn_options;

    /* connections pool */
    struct mk_list conn_queue;
    struct mk_list _head;

    struct flb_pgsql_conn *conn_current;
    int max_pool_size;
    int min_pool_size;
    int active_conn;

    /* async mode or sync mode */
    int async;

    /* cockroachdb */
    int cockroachdb;
};

void pgsql_conf_destroy(struct flb_pgsql_config *ctx);

#endif
