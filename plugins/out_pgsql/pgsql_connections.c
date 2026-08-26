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

#include <fluent-bit/flb_output_plugin.h>

#include "pgsql.h"

void pgsql_destroy_connections(struct flb_pgsql_config *ctx)
{
    PGresult *res = NULL;

    if (ctx->conn_current == NULL) {
        return;
    }

    if (ctx->conn_current != NULL) {
        while ((res = PQgetResult(ctx->conn_current)) != NULL) {
            if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                pgsql_log_result_error(ctx,
                                       "pending result drain",
                                       ctx->conn_current,
                                       res);
            }
            PQclear(res);
        }

        PQfinish(ctx->conn_current);
    }

    ctx->conn_current = NULL;
}

void *pgsql_create_connection(struct flb_pgsql_config *ctx)
{
    PGconn *conn;

    conn = PQsetdbLogin(ctx->db_hostname,
                        ctx->db_port,
                        ctx->conn_options,
                        NULL,
                        ctx->db_name,
                        ctx->db_user,
                        ctx->db_passwd);

    if (conn == NULL) {
        pgsql_log_conn_error(ctx, "PostgreSQL connection", conn);
        return NULL;
    }

    if (PQstatus(conn) != CONNECTION_OK) {
        pgsql_log_conn_error(ctx, "PostgreSQL connection", conn);
        PQfinish(conn);
        return NULL;
    }

    return conn;
}

int pgsql_start_connections(struct flb_pgsql_config *ctx)
{
    PGconn *conn = NULL;

    flb_plg_info(ctx->ins, "opening PostgreSQL connection");

    conn = pgsql_create_connection(ctx);
    if (conn == NULL) {
        return -1;
    }

    ctx->conn_current = conn;

    return 0;
}

int pgsql_next_connection(struct flb_pgsql_config *ctx)
{
    if (ctx->conn_current == NULL) {
        flb_plg_error(ctx->ins, "no PostgreSQL connection available");
        return -1;
    }

    return 0;
}
