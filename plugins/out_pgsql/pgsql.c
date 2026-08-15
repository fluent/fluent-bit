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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "pgsql.h"
#include "pgsql_connections.h"

void pgsql_conf_destroy(struct flb_pgsql_config *ctx)
{
    pgsql_destroy_connections(ctx);

    flb_free(ctx->db_hostname);

    if (ctx->db_table_escaped != NULL) {
        flb_sds_destroy(ctx->db_table_escaped);
    }

    if (ctx->insert_query != NULL) {
        flb_sds_destroy(ctx->insert_query);
    }

    flb_free(ctx);
    ctx = NULL;
}

flb_sds_t pgsql_build_insert_query(const char *table_name, int cockroachdb)
{
    flb_sds_t query;
    size_t query_size;

    query_size = strlen(table_name) + 192;
    query = flb_sds_create_size(query_size);
    if (query == NULL) {
        flb_errno();
        return NULL;
    }

    if (cockroachdb) {
        flb_sds_printf(&query,
                       "INSERT INTO %s (tag, time, data) VALUES ($1, "
                       "DATE '1970-01-01' + ($2::float8 * INTERVAL '1 second'), "
                       "$3::jsonb);",
                       table_name);
    }
    else {
        flb_sds_printf(&query,
                       "INSERT INTO %s (tag, time, data) VALUES ($1, "
                       "to_timestamp($2::double precision), $3::jsonb);",
                       table_name);
    }

    return query;
}

int pgsql_format_timestamp(char *buffer, size_t size, struct flb_time *timestamp)
{
    double timestamp_value;

    timestamp_value = flb_time_to_double(timestamp);

    return snprintf(buffer, size, "%0.9f", timestamp_value);
}

char *pgsql_format_body_json(msgpack_object *body, int escape_unicode)
{
    return flb_msgpack_to_json_str(1024, body, escape_unicode);
}

void pgsql_free_body_json(char *json)
{
    if (json != NULL) {
        flb_free(json);
    }
}

int pgsql_translate_decoder_result(int decoder_result)
{
    if (decoder_result == FLB_EVENT_DECODER_SUCCESS) {
        return FLB_OK;
    }

    if (decoder_result == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA) {
        return FLB_RETRY;
    }

    return FLB_ERROR;
}

const char *pgsql_conn_status_string(ConnStatusType status)
{
    switch (status) {
    PGSQL_CONN_STATUS_MAP(PGSQL_CONN_STATUS_CASE)
    default:
        return "CONNECTION_UNKNOWN";
    }
}

void pgsql_log_conn_error(struct flb_pgsql_config *ctx, const char *action, PGconn *conn)
{
    const char *message;
    ConnStatusType status;

    if (conn == NULL) {
        flb_plg_error(ctx->ins, "%s failed: no PostgreSQL connection handle", action);
        return;
    }

    message = PQerrorMessage(conn);
    status = PQstatus(conn);

    if (message != NULL && message[0] != '\0') {
        flb_plg_error(ctx->ins, "%s failed: %s (status=%s)",
                      action, message, pgsql_conn_status_string(status));
    }
    else {
        flb_plg_error(ctx->ins, "%s failed with empty libpq error (status=%s)",
                      action, pgsql_conn_status_string(status));
    }
}

void pgsql_log_result_error(struct flb_pgsql_config *ctx,
                            const char *action,
                            PGconn *conn,
                            PGresult *res)
{
    const char *message;
    ExecStatusType status;

    if (res == NULL) {
        if (conn != NULL) {
            pgsql_log_conn_error(ctx, action, conn);
        }
        else {
            flb_plg_error(ctx->ins, "%s failed: no PGresult and no connection handle",
                          action);
        }

        return;
    }

    status = PQresultStatus(res);
    message = PQresultErrorMessage(res);

    if (message != NULL && message[0] != '\0') {
        flb_plg_error(ctx->ins, "%s failed: %s (result=%s)",
                      action, message, PQresStatus(status));
    }
    else if (conn != NULL) {
        message = PQerrorMessage(conn);

        if (message != NULL && message[0] != '\0') {
            flb_plg_error(ctx->ins, "%s failed: %s (result=%s, conn_status=%s)",
                          action, message, PQresStatus(status),
                          pgsql_conn_status_string(PQstatus(conn)));
        }
        else {
            flb_plg_error(ctx->ins,
                          "%s failed with empty libpq error (result=%s, conn_status=%s)",
                          action, PQresStatus(status),
                          pgsql_conn_status_string(PQstatus(conn)));
        }
    }
    else {
        flb_plg_error(ctx->ins, "%s failed with empty libpq error (result=%s)",
                      action, PQresStatus(status));
    }
}

static int pgsql_execute_command(struct flb_pgsql_config *ctx,
                                 const char *command,
                                 const char *action)
{
    PGresult *res;

    res = PQexec(ctx->conn_current, command);

    if (res == NULL || PQresultStatus(res) != PGRES_COMMAND_OK) {
        pgsql_log_result_error(ctx, action, ctx->conn_current, res);
        if (res != NULL) {
            PQclear(res);
        }
        return -1;
    }

    PQclear(res);

    return 0;
}

static int pgsql_insert_record(struct flb_pgsql_config *ctx,
                               const char *tag,
                               const char *timestamp,
                               const char *json)
{
    const char *param_values[3];
    PGresult *res;

    param_values[0] = tag;
    param_values[1] = timestamp;
    param_values[2] = json;

    res = PQexecPrepared(ctx->conn_current,
                         FLB_PGSQL_INSERT_STMT_NAME,
                         3,
                         param_values,
                         NULL,
                         NULL,
                         0);

    if (res == NULL || PQresultStatus(res) != PGRES_COMMAND_OK) {
        pgsql_log_result_error(ctx, "record insert", ctx->conn_current, res);
        if (res != NULL) {
            PQclear(res);
        }
        return -1;
    }

    PQclear(res);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "database", FLB_PGSQL_DBNAME,
     0, FLB_TRUE, offsetof(struct flb_pgsql_config, db_name),
     "PostgreSQL database name."
    },
    {
     FLB_CONFIG_MAP_STR, "table", FLB_PGSQL_TABLE,
     0, FLB_TRUE, offsetof(struct flb_pgsql_config, db_table),
     "Destination table name."
    },
    {
     FLB_CONFIG_MAP_STR, "connection_options", NULL,
     0, FLB_TRUE, offsetof(struct flb_pgsql_config, conn_options),
     "Additional PostgreSQL connection options passed to libpq."
    },
    {
     FLB_CONFIG_MAP_STR, "user", NULL,
     0, FLB_TRUE, offsetof(struct flb_pgsql_config, db_user),
     "Database user name."
    },
    {
     FLB_CONFIG_MAP_STR, "password", NULL,
     0, FLB_TRUE, offsetof(struct flb_pgsql_config, db_passwd),
     "Database user password."
    },
    {
     FLB_CONFIG_MAP_BOOL, "cockroachdb", "false",
     0, FLB_TRUE, offsetof(struct flb_pgsql_config, cockroachdb),
     "Enable CockroachDB-compatible timestamp SQL syntax."
    },

    {0}
};

static int pgsql_prepare_insert_statement(struct flb_pgsql_config *ctx)
{
    PGresult *res;

    res = PQprepare(ctx->conn_current,
                    FLB_PGSQL_INSERT_STMT_NAME,
                    ctx->insert_query,
                    3,
                    NULL);
    if (res == NULL || PQresultStatus(res) != PGRES_COMMAND_OK) {
        pgsql_log_result_error(ctx, "prepare insert statement", ctx->conn_current, res);
        if (res != NULL) {
            PQclear(res);
        }
        ctx->insert_statement_prepared = FLB_FALSE;
        return -1;
    }

    PQclear(res);
    ctx->insert_statement_prepared = FLB_TRUE;

    return 0;
}

static int cb_pgsql_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_pgsql_config *ctx;
    size_t str_len;
    PGresult *res;
    char *query = NULL;
    char *temp = NULL;
    int ret;
    (void) config;
    (void) data;

    /* set default network configuration */
    flb_output_net_default(FLB_PGSQL_HOST, FLB_PGSQL_PORT, ins);

    ctx = flb_calloc(1, sizeof(struct flb_pgsql_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, ctx);
    if (ret == -1) {
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* Database host */
    ctx->db_hostname = flb_strdup(ins->host.name);
    if (!ctx->db_hostname) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* Database port */
    snprintf(ctx->db_port, sizeof(ctx->db_port), "%d", ins->host.port);

    if (!ctx->db_table) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    /* db user */
    if (!ctx->db_user) {
        flb_plg_warn(ctx->ins,
                     "You didn't supply a valid user to connect,"
                     "your current unix user will be used");
    }

    ret = pgsql_start_connections(ctx);
    if (ret) {
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "host=%s port=%s dbname=%s OK",
              ctx->db_hostname, ctx->db_port, ctx->db_name);
    temp = PQescapeIdentifier(ctx->conn_current, ctx->db_table,
                              flb_sds_len(ctx->db_table));

    if (temp == NULL) {
        pgsql_log_conn_error(ctx, "table name escaping", ctx->conn_current);
        pgsql_conf_destroy(ctx);
        return -1;
    }

    ctx->db_table_escaped = flb_sds_create(temp);
    PQfreemem(temp);

    if (!ctx->db_table_escaped) {
        flb_errno();
        pgsql_conf_destroy(ctx);
        return -1;
    }

    ctx->insert_query = pgsql_build_insert_query(ctx->db_table_escaped,
                                                 ctx->cockroachdb);
    if (ctx->insert_query == NULL) {
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "we check that the table %s "
                 "exists, if not we create it", ctx->db_table_escaped);

    str_len = 72 + flb_sds_len(ctx->db_table_escaped);

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
             ctx->db_table_escaped);
    flb_plg_trace(ctx->ins, "%s", query);
    res = PQexec(ctx->conn_current, query);

    flb_free(query);

    if (res == NULL || PQresultStatus(res) != PGRES_COMMAND_OK) {
        pgsql_log_result_error(ctx, "table creation", ctx->conn_current, res);
        if (res != NULL) {
            PQclear(res);
        }
        pgsql_conf_destroy(ctx);
        return -1;
    }

    PQclear(res);

    ret = pgsql_prepare_insert_statement(ctx);
    if (ret != 0) {
        pgsql_conf_destroy(ctx);
        return -1;
    }

    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_pgsql_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_pgsql_config *ctx = out_context;
    char *json;
    int decoder_result;
    int flush_result;
    int transaction_started;
    char timestamp_value[64];

    (void) out_flush;
    (void) i_ins;

    flush_result = FLB_OK;
    transaction_started = FLB_FALSE;
    json = NULL;

    if (pgsql_next_connection(ctx) != 0) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /*
     * PQreset()
     * This function will close the connection to the server and attempt to
     * reestablish a new connection to the same server, using all the same
     * parameters previously used. This might be useful for error recovery
     * if a working connection is lost.
     */
    if (PQstatus(ctx->conn_current) != CONNECTION_OK) {
        ctx->insert_statement_prepared = FLB_FALSE;
        PQreset(ctx->conn_current);
        if (PQstatus(ctx->conn_current) != CONNECTION_OK) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        if (pgsql_prepare_insert_statement(ctx) != 0) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }
    else if (ctx->insert_statement_prepared == FLB_FALSE) {
        if (pgsql_prepare_insert_statement(ctx) != 0) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    decoder_result = flb_log_event_decoder_init(&log_decoder,
                                                (char *) event_chunk->data,
                                                event_chunk->size);
    if (decoder_result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d",
                      decoder_result);
        FLB_OUTPUT_RETURN(pgsql_translate_decoder_result(decoder_result));
    }

    if (pgsql_execute_command(ctx, "BEGIN", "transaction begin") != 0) {
        flb_log_event_decoder_destroy(&log_decoder);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    transaction_started = FLB_TRUE;

    while (flb_log_event_decoder_next(&log_decoder,
                                      &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        json = pgsql_format_body_json(log_event.body, config->json_escape_unicode);
        if (json == NULL) {
            flb_errno();
            flb_plg_error(ctx->ins, "Can't parse the msgpack record into json");
            flush_result = FLB_RETRY;
            goto cleanup;
        }

        pgsql_format_timestamp(timestamp_value, sizeof(timestamp_value),
                               &log_event.timestamp);

        if (pgsql_insert_record(ctx,
                                event_chunk->tag,
                                timestamp_value,
                                json) != 0) {
            flush_result = FLB_RETRY;
            goto cleanup;
        }

        flb_plg_trace(ctx->ins, "inserted record with timestamp=%s",
                      timestamp_value);
        pgsql_free_body_json(json);
        json = NULL;
    }

    decoder_result = flb_log_event_decoder_get_last_result(&log_decoder);

    if (decoder_result != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder error : %d", decoder_result);
        flush_result = pgsql_translate_decoder_result(decoder_result);
        goto cleanup;
    }

    if (pgsql_execute_command(ctx, "COMMIT", "transaction commit") != 0) {
        flush_result = FLB_RETRY;
        goto cleanup;
    }

    transaction_started = FLB_FALSE;
    flb_log_event_decoder_destroy(&log_decoder);
    FLB_OUTPUT_RETURN(FLB_OK);

cleanup:
    if (json != NULL) {
        pgsql_free_body_json(json);
    }

    if (transaction_started) {
        pgsql_execute_command(ctx, "ROLLBACK", "transaction rollback");
    }

    flb_log_event_decoder_destroy(&log_decoder);
    FLB_OUTPUT_RETURN(flush_result);
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
    .event_type   = FLB_OUTPUT_LOGS,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET,
    .workers      = 1,
};
