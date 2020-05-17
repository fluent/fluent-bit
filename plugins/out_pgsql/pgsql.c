/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>

#include "pgsql.h"

void pgsql_conf_destroy(struct flb_pgsql_config *ctx)
{
    PGresult *res = NULL;

    if(PQstatus(ctx->conn) == CONNECTION_OK) {
        while(PQconsumeInput(ctx->conn) == 0) {
            res = PQgetResult(ctx->conn);
            if(PQresultStatus(res) != PGRES_COMMAND_OK) {
                flb_warn("[out_pgsql] %s", PQerrorMessage(ctx->conn));
            }
            PQclear(res);
        }
    }

    flb_free(ctx->db_hostname);

    if(ctx->db_table != NULL) {
        flb_sds_destroy(ctx->db_table);
    }

    if(ctx->timestamp_key != NULL) {
        flb_sds_destroy(ctx->timestamp_key);
    }

    PQfinish(ctx->conn);

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

    /* set default network configuration */
    flb_output_net_default(FLB_PGSQL_HOST, FLB_PGSQL_PORT, ins);

    ctx = flb_calloc(1, sizeof(struct flb_pgsql_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->db_hostname = flb_strdup(ins->host.name);
    if(!ctx->db_hostname) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    snprintf(ctx->db_port, sizeof(ctx->db_port), "%d", ins->host.port);


    ctx->db_name = flb_output_get_property("database", ins);
    if(!ctx->db_name) {
        ctx->db_name = FLB_PGSQL_DBNAME;
    }

    tmp = flb_output_get_property("table", ins);
    if(tmp) {
        ctx->db_table = flb_sds_create(tmp);
    }
    else {
        ctx->db_table = flb_sds_create(FLB_PGSQL_TABLE);
    }

    if(!ctx->db_table) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    ctx->db_user = flb_output_get_property("user", ins);
    if(!ctx->db_user) {
        flb_warn("[out_pgsql] You didn't supply a valid user to connect,"
                 "your current unix user will be used");
    }

    ctx->db_passwd = flb_output_get_property("password", ins);
    if(!ctx->db_passwd) {
        flb_warn("[out_pgsql] You didn't supply a password, you should"
                 "use a password to authenticate against PostgreSQL");
    }

    tmp = flb_output_get_property("timestamp_key", ins);
    if(tmp) {
        ctx->timestamp_key = flb_sds_create(tmp);
    }
    else {
        ctx->timestamp_key = flb_sds_create(FLB_PGSQL_TIMESTAMP_KEY);
    }

    if(!ctx->timestamp_key) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_info("[out_pgsql] host=%s port=%s dbname=%s ...",
             ctx->db_hostname, ctx->db_port, ctx->db_name);

    ctx->conn = PQsetdbLogin(ctx->db_hostname,
                             ctx->db_port,
                             NULL, NULL,
                             ctx->db_name,
                             ctx->db_user,
                             ctx->db_passwd);

    if(PQstatus(ctx->conn) != CONNECTION_OK) {
        flb_error("[out_pgsql] failed to connect to host=%s with error: %s",
                  ctx->db_hostname, PQerrorMessage(ctx->conn));
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_info("[out_pgsql] host=%s port=%s dbname=%s OK",
              ctx->db_hostname, ctx->db_port, ctx->db_name);
    flb_output_set_context(ins, ctx);

    temp = PQescapeIdentifier(ctx->conn, ctx->db_table,
                              flb_sds_len(ctx->db_table));

    if(temp == NULL) {
        flb_error("[out_pgsql] failed to parse table name: %s",
                  PQerrorMessage(ctx->conn));
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_sds_destroy(ctx->db_table);
    ctx->db_table = flb_sds_create(temp);
    PQfreemem(temp);

    if(!ctx->db_table) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_info("[out_pgsql] we check that the table %s "
             "exists, if not we create it", ctx->db_table);

    str_len = 72 + flb_sds_len(ctx->db_table);

    query = flb_malloc(str_len);
    if(query == NULL) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* Maybe use the timestamp with the TZ specefied */
    /* in the postgresql connection? */
    snprintf(query, str_len,
             "CREATE TABLE IF NOT EXISTS %s "
             "(tag varchar, time timestamp, data jsonb);",
             ctx->db_table);
    res = PQexec(ctx->conn, query);
    flb_free(query);

    if(PQresultStatus(res) != PGRES_COMMAND_OK) {
        flb_error("[out_pgsql] %s", PQerrorMessage(ctx->conn));
        pgsql_conf_destroy(ctx);
        return -1;
    }

    PQclear(res);

    flb_info("[out_pgsql] switching postgresql connection "
             "to non-blocking mode");
    if(PQsetnonblocking(ctx->conn, 1) != 0) {
        flb_error("[out_pgsql] non-blocking mode not set");
        pgsql_conf_destroy(ctx);
        return -1;
    }

    return 0;
}

static void cb_pgsql_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    struct flb_pgsql_config *ctx = out_context;
    flb_sds_t json;
    char *tmp = NULL;
    PGresult *res = NULL;
    char *query = NULL;
    flb_sds_t tag_escaped = NULL;
    size_t str_len;

    if(PQconsumeInput(ctx->conn) == 0 && PQisBusy(ctx->conn) == 1) {
        flb_debug("[out_pgsql] Some command may still be running");
    }

    /*
      PQreset()
      This function will close the connection to the server and attempt to
      reestablish a new connection to the same server, using all the same
      parameters previously used. This might be useful for error recovery
      if a working connection is lost.
     */
    if(PQstatus(ctx->conn) != CONNECTION_OK) {
        PQreset(ctx->conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }


    json = flb_pack_msgpack_to_json_format(data, bytes,
                                           FLB_PACK_JSON_FORMAT_JSON,
                                           FLB_PACK_JSON_DATE_DOUBLE,
                                           ctx->timestamp_key);
    if(json == NULL) {
        flb_errno();
        flb_error("[out_pgsql] Can't parse the msgpack into json");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    tmp = PQescapeLiteral(ctx->conn, json, flb_sds_len(json));
    flb_sds_destroy(json);
    if(!tmp) {
        flb_errno();
        PQfreemem(tmp);
        flb_error("[out_pgsql] Can't escape json string");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    json = flb_sds_create(tmp);
    PQfreemem(tmp);
    if(!json) {
        flb_errno();
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    tmp = PQescapeLiteral(ctx->conn, tag, tag_len);
    if(!tmp) {
        flb_errno();
        flb_sds_destroy(json);
        PQfreemem(tmp);
        flb_error("[out_pgsql] Can't escape tag string: %s", tag);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    tag_escaped = flb_sds_create(tmp);
    PQfreemem(tmp);
    if(!tag_escaped) {
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


    /*
      We should call PQgetResult() until get NULL
      This fix some issues in this previous release
      in a future release we will provide two modes
      sync and async to send data to PostgreSQL
    */
    res = PQgetResult(ctx->conn);
    while(res != NULL) {
        PQclear(res);
        res = PQgetResult(ctx->conn);
    }

    snprintf(query, str_len,
             "INSERT INTO %s "
             "SELECT %s, "
             "to_timestamp(CAST(value->>'%s' as FLOAT)), * "
             "FROM json_array_elements(%s);",
             ctx->db_table, tag_escaped, ctx->timestamp_key, json);

    PQsendQuery(ctx->conn, query);
    flb_free(query);
    flb_sds_destroy(json);
    flb_sds_destroy(tag_escaped);

    PQflush(ctx->conn);

    if(PQisBusy(ctx->conn) == 0) {
        res = PQgetResult(ctx->conn);
        if(PQresultStatus(res) != PGRES_COMMAND_OK) {
            flb_debug("[out_pgsql] %s", PQerrorMessage(ctx->conn));
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

    if(!ctx){
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
