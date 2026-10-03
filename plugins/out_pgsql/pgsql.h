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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_output_plugin.h>

#include <libpq-fe.h>
#include <msgpack.h>

#define FLB_PGSQL_HOST "127.0.0.1"
#define FLB_PGSQL_PORT 5432
#define FLB_PGSQL_DBNAME "fluentbit"
#define FLB_PGSQL_TABLE "fluentbit"
#define FLB_PGSQL_COCKROACH FLB_FALSE
#define FLB_PGSQL_INSERT_STMT_NAME "flb_pgsql_insert"

#define PGSQL_CONN_STATUS_CASE(name) \
    case name:                       \
        return #name;

#define PGSQL_CONN_STATUS_MAP(ENTRY)     \
    ENTRY(CONNECTION_OK)                 \
    ENTRY(CONNECTION_BAD)                \
    ENTRY(CONNECTION_STARTED)            \
    ENTRY(CONNECTION_MADE)               \
    ENTRY(CONNECTION_AWAITING_RESPONSE)  \
    ENTRY(CONNECTION_AUTH_OK)            \
    ENTRY(CONNECTION_SETENV)             \
    ENTRY(CONNECTION_SSL_STARTUP)        \
    ENTRY(CONNECTION_NEEDED)

struct flb_pgsql_config {

    /* database */
    char *db_hostname;
    char db_port[8];
    const char *db_name;
    flb_sds_t db_table;
    flb_sds_t db_table_escaped;

    /* auth */
    const char *db_user;
    const char *db_passwd;

    /* instance reference */
    struct flb_output_instance *ins;

    /* connections options */
    const char *conn_options;

    PGconn *conn_current;
    flb_sds_t insert_query;
    int insert_statement_prepared;

    /* cockroachdb */
    int cockroachdb;
};

flb_sds_t pgsql_build_insert_query(const char *table_name, int cockroachdb);
int pgsql_format_timestamp(char *buffer, size_t size, struct flb_time *timestamp);
char *pgsql_format_body_json(msgpack_object *body, int escape_unicode);
void pgsql_free_body_json(char *json);
int pgsql_translate_decoder_result(int decoder_result);
const char *pgsql_conn_status_string(ConnStatusType status);
void pgsql_log_conn_error(struct flb_pgsql_config *ctx, const char *action, PGconn *conn);
void pgsql_log_result_error(struct flb_pgsql_config *ctx,
                            const char *action,
                            PGconn *conn,
                            PGresult *res);
void pgsql_conf_destroy(struct flb_pgsql_config *ctx);

#endif
