/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>

#include "pgsql.h"
#include "pgsql_connections.h"

void pgsql_conf_destroy(struct flb_pgsql_config *ctx)
{
    pgsql_destroy_connections(ctx);

    flb_free(ctx->db_hostname);

    if (ctx->db_table != NULL) {
        flb_sds_destroy(ctx->db_table);
    }

    if (ctx->timestamp_key != NULL) {
        flb_sds_destroy(ctx->timestamp_key);
    }

    flb_free(ctx);
    ctx = NULL;
}

static int cb_pgsql_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{

    struct flb_pgsql_config *ctx;
    size_t str_len;
    PGresult *res;
    char *query = NULL;
    char *temp = NULL;
    const char *tmp = NULL;
    int ret;

    /* set default network configuration */
    flb_output_net_default(FLB_PGSQL_HOST, FLB_PGSQL_PORT, ins);

    ctx = flb_calloc(1, sizeof(struct flb_pgsql_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;

    /* Database host */
    ctx->db_hostname = flb_strdup(ins->host.name);
    if (!ctx->db_hostname) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* Database port */
    snprintf(ctx->db_port, sizeof(ctx->db_port), "%d", ins->host.port);

    /* Database name */
    ctx->db_name = flb_output_get_property("database", ins);
    if (!ctx->db_name) {
        ctx->db_name = FLB_PGSQL_DBNAME;
    }

    /* db table */
    tmp = flb_output_get_property("table", ins);
    if (tmp) {
        ctx->db_table = flb_sds_create(tmp);
    }
    else {
        ctx->db_table = flb_sds_create(FLB_PGSQL_TABLE);
    }

    /* connection options */
    ctx->conn_options = flb_output_get_property("connection_options", ins);

    if (!ctx->db_table) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* db user */
    ctx->db_user = flb_output_get_property("user", ins);
    if (!ctx->db_user) {
        flb_plg_warn(ctx->ins,
                     "You didn't supply a valid user to connect,"
                     "your current unix user will be used");
    }

    /* db user password */
    ctx->db_passwd = flb_output_get_property("password", ins);

    /* timestamp key */
    tmp = flb_output_get_property("timestamp_key", ins);
    if (tmp) {
        ctx->timestamp_key = flb_sds_create(tmp);
    }
    else {
        ctx->timestamp_key = flb_sds_create(FLB_PGSQL_TIMESTAMP_KEY);
    }

    if (!ctx->timestamp_key) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* Pool size */
    tmp = flb_output_get_property("max_pool_size", ins);
    if (tmp) {
        ctx->max_pool_size = strtol(tmp, NULL, 0);
        if (ctx->max_pool_size < 1)
            ctx->max_pool_size = 1;
    }
    else {
        ctx->max_pool_size = FLB_PGSQL_POOL_SIZE;
    }

    tmp = flb_output_get_property("min_pool_size", ins);
    if (tmp) {
        ctx->min_pool_size = strtol(tmp, NULL, 0);
        if (ctx->min_pool_size < 1 || ctx->min_pool_size > ctx->max_pool_size)
            ctx->min_pool_size = ctx->max_pool_size;
    }
    else {
        ctx->min_pool_size = FLB_PGSQL_MIN_POOL_SIZE;
    }

    /* Sync Mode */
    tmp = flb_output_get_property("async", ins);
    if (tmp && flb_utils_bool(tmp)) {
        ctx->async = FLB_TRUE;
    }
    else {
        ctx->async = FLB_FALSE;
    }

    if (!ctx->async) {
        ctx->min_pool_size = 1;
        ctx->max_pool_size = 1;
    }

    /* CockroachDB Support */
    tmp = flb_output_get_property("cockroachdb", ins);
    if (tmp && flb_utils_bool(tmp)) {
        ctx->cockroachdb = FLB_TRUE;
    }
    else {
        ctx->cockroachdb = FLB_FALSE;
    }

    ret = pgsql_start_connections(ctx);
    if (ret) {
        return -1;
    }

    flb_plg_info(ctx->ins, "host=%s port=%s dbname=%s OK",
              ctx->db_hostname, ctx->db_port, ctx->db_name);
    flb_output_set_context(ins, ctx);

    temp = PQescapeIdentifier(ctx->conn_current->conn, ctx->db_table,
                              flb_sds_len(ctx->db_table));

    if (temp == NULL) {
        flb_plg_error(ctx->ins, "failed to parse table name: %s",
                      PQerrorMessage(ctx->conn_current->conn));
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_sds_destroy(ctx->db_table);
    ctx->db_table = flb_sds_create(temp);
    PQfreemem(temp);

    if (!ctx->db_table) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "we check that the table %s "
                 "exists, if not we create it", ctx->db_table);

    str_len = 72 + flb_sds_len(ctx->db_table);

    query = flb_malloc(str_len);
    if (query == NULL) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* Maybe use the timestamp with the TZ specified */
    /* in the postgresql connection? */
    snprintf(query, str_len,
             "CREATE TABLE IF NOT EXISTS %s "
             "(tag varchar, time timestamp, data jsonb);",
             ctx->db_table);
    flb_plg_trace(ctx->ins, "%s", query);
    res = PQexec(ctx->conn_current->conn, query);

    flb_free(query);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        flb_plg_error(ctx->ins, "%s",
                      PQerrorMessage(ctx->conn_current->conn));
        pgsql_conf_destroy(ctx);
        return -1;
    }

    PQclear(res);

    return 0;
}

static void cb_pgsql_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    struct flb_pgsql_config *ctx = out_context;
    flb_sds_t json;
    char *tmp = NULL;
    char *query = NULL;
    PGresult *res = NULL;
    int send_res;
    flb_sds_t tag_escaped = NULL;
    size_t str_len;


    if (pgsql_next_connection(ctx) == 1) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /*
     * PQreset()
     * This function will close the connection to the server and attempt to
     * reestablish a new connection to the same server, using all the same
     * parameters previously used. This might be useful for error recovery
     * if a working connection is lost.
     */
    if (PQstatus(ctx->conn_current->conn) != CONNECTION_OK) {
        PQreset(ctx->conn_current->conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    json = flb_pack_msgpack_to_json_format(event_chunk->data,
                                           event_chunk->size,
                                           FLB_PACK_JSON_FORMAT_JSON,
                                           FLB_PACK_JSON_DATE_DOUBLE,
                                           ctx->timestamp_key,
                                           config->json_escape_unicode);
    if (json == NULL) {
        flb_errno();
        flb_plg_error(ctx->ins,
                      "Can't parse the msgpack into json");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    tmp = PQescapeLiteral(ctx->conn_current->conn, json, flb_sds_len(json));
    flb_sds_destroy(json);
    if (!tmp) {
        flb_errno();
        PQfreemem(tmp);
        flb_plg_error(ctx->ins, "Can't escape json string");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    json = flb_sds_create(tmp);
    PQfreemem(tmp);
    if (!json) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    tmp = PQescapeLiteral(ctx->conn_current->conn,
                          event_chunk->tag,
                          flb_sds_len(event_chunk->tag));
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(json);
        PQfreemem(tmp);
        flb_plg_error(ctx->ins, "Can't escape tag string: %s",
                      event_chunk->tag);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    tag_escaped = flb_sds_create(tmp);
    PQfreemem(tmp);
    if (!tag_escaped) {
        flb_errno();
        flb_sds_destroy(json);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    str_len = 100 + flb_sds_len(json)
        + flb_sds_len(tag_escaped)
        + flb_sds_len(ctx->db_table)
        + flb_sds_len(ctx->timestamp_key);
    query = flb_malloc(str_len);

    if (query == NULL) {
        flb_errno();
        flb_sds_destroy(json);
        flb_sds_destroy(tag_escaped);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }


    snprintf(query, str_len,
             ctx->cockroachdb ? FLB_PGSQL_INSERT_COCKROACH : FLB_PGSQL_INSERT,
             ctx->db_table, tag_escaped, ctx->timestamp_key, json);
    flb_plg_trace(ctx->ins, "query: %s", query);

    if (ctx->async) {
        send_res = PQsendQuery(ctx->conn_current->conn, query);
        flb_free(query);
        flb_sds_destroy(json);
        flb_sds_destroy(tag_escaped);

        if (send_res == 0) {
            flb_plg_error(ctx->ins, "%s",
                          PQerrorMessage(ctx->conn_current->conn));
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        PQflush(ctx->conn_current->conn);
    }
    else {
        res = PQexec(ctx->conn_current->conn, query);
        flb_free(query);
        flb_sds_destroy(json);
        flb_sds_destroy(tag_escaped);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            flb_plg_error(ctx->ins, "%s",
                          PQerrorMessage(ctx->conn_current->conn));
            PQclear(res);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        PQclear(res);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_pgsql_exit(void *data, struct flb_config *config)
{
    struct flb_pgsql_config *ctx = data;

    if (!ctx){
        return 0;
    }

    pgsql_conf_destroy(ctx);

    return 0;
}

struct flb_output_plugin out_pgsql_plugin = {
    .name         = "pgsql",
    .description  = "PostgreSQL",
    .cb_init      = cb_pgsql_init,
    .cb_flush     = cb_pgsql_flush,
    .cb_exit      = cb_pgsql_exit,
    .flags        = 0,
};
