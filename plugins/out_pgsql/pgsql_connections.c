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
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_pgsql_conn *conn;
    PGresult *res = NULL;

    mk_list_foreach_safe(head, tmp, &ctx->conn_queue) {
        conn = mk_list_entry(head, struct flb_pgsql_conn, _head);
        if (PQstatus(conn->conn) == CONNECTION_OK) {
            while(PQconsumeInput(conn->conn) == 0) {
                res = PQgetResult(conn->conn);
                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                    flb_plg_warn(ctx->ins, "%s",
                                 PQerrorMessage(conn->conn));
                }
                PQclear(res);
            }
        }
        PQfinish(conn->conn);
        flb_free(conn);
    }
}

void *pgsql_create_connection(struct flb_pgsql_config *ctx)
{
    struct flb_pgsql_conn *conn;

    conn = flb_calloc(1, sizeof(struct flb_pgsql_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    conn->conn = PQsetdbLogin(ctx->db_hostname,
                              ctx->db_port,
                              ctx->conn_options,
                              NULL,
                              ctx->db_name,
                              ctx->db_user,
                              ctx->db_passwd);

    if (PQstatus(conn->conn) != CONNECTION_OK) {
        flb_plg_error(ctx->ins,
                      "failed connecting to host=%s with error: %s",
                      ctx->db_hostname, PQerrorMessage(conn->conn));
        PQfinish(conn->conn);
        flb_free(conn);
        return NULL;
    }

    flb_plg_info(ctx->ins, "switching postgresql connection "
                 "to non-blocking mode");

    if (PQsetnonblocking(conn->conn, 1) != 0) {
        flb_plg_error(ctx->ins, "non-blocking mode not set");
        PQfinish(conn->conn);
        flb_free(conn);
        return NULL;
    }

    return conn;
}

int pgsql_start_connections(struct flb_pgsql_config *ctx)
{
    int i;
    struct flb_pgsql_conn *conn = NULL;

    mk_list_init(&ctx->conn_queue);
    ctx->active_conn = 0;

    for(i = 0; i < ctx->min_pool_size; i++) {
        flb_plg_info(ctx->ins, "Opening connection: #%d", i);

        conn = (struct flb_pgsql_conn *)pgsql_create_connection(ctx);
        if (conn == NULL) {
            pgsql_conf_destroy(ctx);
            return -1;
        }

        conn->number = i;
        ctx->active_conn++;
        mk_list_add(&conn->_head, &ctx->conn_queue);
    }

    ctx->conn_current = mk_list_entry_last(&ctx->conn_queue,
                                           struct flb_pgsql_conn,
                                           _head);

    return 0;
}

int pgsql_new_connection(struct flb_pgsql_config *ctx)
{
    struct flb_pgsql_conn *conn = NULL;

    if (ctx->active_conn >= ctx->max_pool_size) {
        return -1;
    }

    conn = (struct flb_pgsql_conn *)pgsql_create_connection(ctx);
    if (conn == NULL) {
        pgsql_conf_destroy(ctx);
        return -1;
    }

    conn->number = ctx->active_conn + 1;
    ctx->active_conn++;

    mk_list_add(&conn->_head, &ctx->conn_queue);

    return 0;
}

int pgsql_next_connection(struct flb_pgsql_config *ctx)
{
    struct flb_pgsql_conn *tmp = NULL;
    PGresult *res = NULL;
    struct mk_list *head;
    int ret_conn = 1;

    if (ctx == NULL) {
        return 1;
    }

    if (PQconsumeInput(ctx->conn_current->conn) == 1) {
        if (PQisBusy(ctx->conn_current->conn) == 0) {
            res = PQgetResult(ctx->conn_current->conn);
            PQclear(res);
        }
    }
    else {
        flb_plg_error(ctx->ins, "%s",
                      PQerrorMessage(ctx->conn_current->conn));
    }

    mk_list_foreach(head, &ctx->conn_queue) {
        tmp = mk_list_entry(head, struct flb_pgsql_conn, _head);
        if (ctx->conn_current == NULL) {
            ctx->conn_current = tmp;
            break;
        }

        res = PQgetResult(tmp->conn);

        if (res == NULL) {
            flb_plg_debug(ctx->ins, "Connection number %d",
                          tmp->number);
            ctx->conn_current = tmp;
            PQclear(res);
            return 0;
        }

        if (PQresultStatus(res) == PGRES_FATAL_ERROR) {
            flb_plg_info(ctx->ins, "%s",
                         PQerrorMessage(tmp->conn));
        }

        PQclear(res);
    }

    if (pgsql_new_connection(ctx) == -1) {
        flb_plg_warn(ctx->ins,
                     "No more free connections."
                     " Increase max connections");
    }
    else {
        flb_plg_warn(ctx->ins, "Added new connection");
        ret_conn = pgsql_next_connection(ctx);
    }

    return ret_conn;
}
