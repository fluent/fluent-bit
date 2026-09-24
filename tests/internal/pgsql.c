/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>

#include <libpq-fe.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

struct pg_conn {
    ConnStatusType status;
    ConnStatusType reset_status;
    const char *error_message;
};

struct pg_result {
    ExecStatusType status;
    const char *error_message;
};

struct pgsql_test_libpq_state {
    size_t active_results;
    size_t begin_calls;
    size_t commit_calls;
    size_t rollback_calls;
    size_t pqexec_calls;
    size_t pqprepare_calls;
    size_t pqexec_prepared_calls;
    size_t pqreset_calls;
    size_t pqfinish_calls;
    size_t pqsetdb_calls;
    size_t pqget_result_calls;
    size_t pqescape_identifier_calls;
    size_t insert_failure_call;
    int pqsetdb_return_null;
    int decoder_init_result;
    ExecStatusType prepare_status;
    ExecStatusType begin_status;
    ExecStatusType commit_status;
    ExecStatusType rollback_status;
    ExecStatusType exec_prepared_failure_status;
    ConnStatusType exec_prepared_failure_conn_status;
    const char *result_error_message;
};

static struct pgsql_test_libpq_state pgsql_test_libpq_state;
static int pgsql_test_flush_result;

static void pgsql_test_libpq_reset(void)
{
    memset(&pgsql_test_libpq_state, 0, sizeof(pgsql_test_libpq_state));

    pgsql_test_libpq_state.prepare_status = PGRES_COMMAND_OK;
    pgsql_test_libpq_state.begin_status = PGRES_COMMAND_OK;
    pgsql_test_libpq_state.commit_status = PGRES_COMMAND_OK;
    pgsql_test_libpq_state.rollback_status = PGRES_COMMAND_OK;
    pgsql_test_libpq_state.exec_prepared_failure_status = PGRES_FATAL_ERROR;
    pgsql_test_libpq_state.exec_prepared_failure_conn_status = CONNECTION_BAD;
    pgsql_test_libpq_state.decoder_init_result = FLB_EVENT_DECODER_SUCCESS;
    pgsql_test_libpq_state.result_error_message = "mock libpq failure";
}

static PGresult *pgsql_test_result_create(ExecStatusType status,
                                          const char *error_message)
{
    struct pg_result *result;

    result = calloc(1, sizeof(struct pg_result));
    if (result == NULL) {
        return NULL;
    }

    result->status = status;
    result->error_message = error_message != NULL ? error_message : "";
    pgsql_test_libpq_state.active_results++;

    return (PGresult *) result;
}

PGconn *PQsetdbLogin(const char *pghost, const char *pgport,
                     const char *pgoptions, const char *pgtty,
                     const char *dbName, const char *login,
                     const char *pwd)
{
    struct pg_conn *conn;

    (void) pghost;
    (void) pgport;
    (void) pgoptions;
    (void) pgtty;
    (void) dbName;
    (void) login;
    (void) pwd;

    pgsql_test_libpq_state.pqsetdb_calls++;

    if (pgsql_test_libpq_state.pqsetdb_return_null) {
        return NULL;
    }

    conn = calloc(1, sizeof(struct pg_conn));
    if (conn == NULL) {
        return NULL;
    }

    conn->status = CONNECTION_OK;
    conn->reset_status = CONNECTION_OK;
    conn->error_message = "mock connection error";

    return (PGconn *) conn;
}

void PQfinish(PGconn *conn)
{
    pgsql_test_libpq_state.pqfinish_calls++;
    free(conn);
}

ConnStatusType PQstatus(const PGconn *conn)
{
    const struct pg_conn *connection;

    connection = (const struct pg_conn *) conn;

    return connection->status;
}

char *PQerrorMessage(const PGconn *conn)
{
    const struct pg_conn *connection;

    connection = (const struct pg_conn *) conn;

    return (char *) connection->error_message;
}

PGresult *PQexec(PGconn *conn, const char *query)
{
    struct pg_conn *connection;

    connection = (struct pg_conn *) conn;
    pgsql_test_libpq_state.pqexec_calls++;

    if (strcmp(query, "BEGIN") == 0) {
        pgsql_test_libpq_state.begin_calls++;
        return pgsql_test_result_create(pgsql_test_libpq_state.begin_status,
                                        pgsql_test_libpq_state.result_error_message);
    }

    if (strcmp(query, "COMMIT") == 0) {
        pgsql_test_libpq_state.commit_calls++;
        return pgsql_test_result_create(pgsql_test_libpq_state.commit_status,
                                        pgsql_test_libpq_state.result_error_message);
    }

    if (strcmp(query, "ROLLBACK") == 0) {
        pgsql_test_libpq_state.rollback_calls++;
        return pgsql_test_result_create(pgsql_test_libpq_state.rollback_status,
                                        pgsql_test_libpq_state.result_error_message);
    }

    if (connection->error_message == NULL) {
        connection->error_message = "mock connection error";
    }

    return pgsql_test_result_create(PGRES_COMMAND_OK, "");
}

PGresult *PQprepare(PGconn *conn, const char *stmtName, const char *query,
                    int nParams, const Oid *paramTypes)
{
    (void) conn;
    (void) stmtName;
    (void) query;
    (void) nParams;
    (void) paramTypes;

    pgsql_test_libpq_state.pqprepare_calls++;

    return pgsql_test_result_create(pgsql_test_libpq_state.prepare_status,
                                    pgsql_test_libpq_state.result_error_message);
}

PGresult *PQexecPrepared(PGconn *conn, const char *stmtName, int nParams,
                         const char *const *paramValues,
                         const int *paramLengths,
                         const int *paramFormats,
                         int resultFormat)
{
    struct pg_conn *connection;

    (void) stmtName;
    (void) nParams;
    (void) paramValues;
    (void) paramLengths;
    (void) paramFormats;
    (void) resultFormat;

    connection = (struct pg_conn *) conn;
    pgsql_test_libpq_state.pqexec_prepared_calls++;

    if (pgsql_test_libpq_state.insert_failure_call != 0 &&
        pgsql_test_libpq_state.pqexec_prepared_calls ==
        pgsql_test_libpq_state.insert_failure_call) {
        connection->status =
            pgsql_test_libpq_state.exec_prepared_failure_conn_status;
        connection->error_message = pgsql_test_libpq_state.result_error_message;

        return pgsql_test_result_create(
                   pgsql_test_libpq_state.exec_prepared_failure_status,
                   pgsql_test_libpq_state.result_error_message);
    }

    return pgsql_test_result_create(PGRES_COMMAND_OK, "");
}

ExecStatusType PQresultStatus(const PGresult *res)
{
    const struct pg_result *result;

    result = (const struct pg_result *) res;

    return result->status;
}

char *PQresultErrorMessage(const PGresult *res)
{
    const struct pg_result *result;

    result = (const struct pg_result *) res;

    return (char *) result->error_message;
}

char *PQresStatus(ExecStatusType status)
{
    switch (status) {
    case PGRES_COMMAND_OK:
        return "PGRES_COMMAND_OK";
    case PGRES_FATAL_ERROR:
        return "PGRES_FATAL_ERROR";
    default:
        return "PGRES_UNKNOWN";
    }
}

void PQclear(PGresult *res)
{
    pgsql_test_libpq_state.active_results--;
    free(res);
}

PGresult *PQgetResult(PGconn *conn)
{
    (void) conn;

    pgsql_test_libpq_state.pqget_result_calls++;

    return NULL;
}

void PQreset(PGconn *conn)
{
    struct pg_conn *connection;

    connection = (struct pg_conn *) conn;
    connection->status = connection->reset_status;
    pgsql_test_libpq_state.pqreset_calls++;
}

char *PQescapeIdentifier(PGconn *conn, const char *str, size_t len)
{
    char *buffer;

    (void) conn;

    buffer = malloc(len + 3);
    if (buffer == NULL) {
        return NULL;
    }

    buffer[0] = '"';
    memcpy(&buffer[1], str, len);
    buffer[len + 1] = '"';
    buffer[len + 2] = '\0';
    pgsql_test_libpq_state.pqescape_identifier_calls++;

    return buffer;
}

void PQfreemem(void *ptr)
{
    free(ptr);
}

/* Capture cb_pgsql_flush() return codes when compiling the plugin inline. */
#undef FLB_OUTPUT_RETURN
#define FLB_OUTPUT_RETURN(x)        \
    do {                            \
        pgsql_test_flush_result = x; \
        return;                     \
    } while (0)

static int pgsql_test_flb_log_event_decoder_init(
    struct flb_log_event_decoder *context,
    char *input_buffer,
    size_t input_length);

#define flb_log_event_decoder_init pgsql_test_flb_log_event_decoder_init
#include "../../plugins/out_pgsql/pgsql.c"
#undef flb_log_event_decoder_init
#include "../../plugins/out_pgsql/pgsql_connections.c"

static int pgsql_test_flb_log_event_decoder_init(
    struct flb_log_event_decoder *context,
    char *input_buffer,
    size_t input_length)
{
    if (pgsql_test_libpq_state.decoder_init_result !=
        FLB_EVENT_DECODER_SUCCESS) {
        return pgsql_test_libpq_state.decoder_init_result;
    }

    return flb_log_event_decoder_init(context, input_buffer, input_length);
}

static void pack_test_body(msgpack_sbuffer *sbuf,
                           msgpack_unpacked *unpacked,
                           msgpack_object **body)
{
    size_t off = 0;

    msgpack_sbuffer_init(sbuf);

    {
        msgpack_packer pck;

        msgpack_packer_init(&pck, sbuf, msgpack_sbuffer_write);
        msgpack_pack_map(&pck, 2);

        msgpack_pack_str(&pck, 7);
        msgpack_pack_str_body(&pck, "message", 7);
        msgpack_pack_str(&pck, 5);
        msgpack_pack_str_body(&pck, "hello", 5);

        msgpack_pack_str(&pck, 5);
        msgpack_pack_str_body(&pck, "value", 5);
        msgpack_pack_int(&pck, 1);
    }

    msgpack_unpacked_init(unpacked);
    TEST_CHECK(msgpack_unpack_next(unpacked, sbuf->data, sbuf->size, &off));

    *body = unpacked->data.via.map.ptr != NULL ? &unpacked->data : NULL;
}

static int pgsql_test_context_init(struct flb_pgsql_config *ctx,
                                   struct flb_output_instance *ins,
                                   struct flb_output_plugin *plugin,
                                   struct pg_conn *conn)
{
    memset(ctx, 0, sizeof(struct flb_pgsql_config));
    memset(ins, 0, sizeof(struct flb_output_instance));
    memset(plugin, 0, sizeof(struct flb_output_plugin));
    memset(conn, 0, sizeof(struct pg_conn));

    plugin->name = "pgsql";
    ins->p = plugin;
    ins->log_level = FLB_LOG_OFF;

    conn->status = CONNECTION_OK;
    conn->reset_status = CONNECTION_OK;
    conn->error_message = "mock connection error";

    ctx->ins = ins;
    ctx->conn_current = (PGconn *) conn;
    ctx->insert_statement_prepared = FLB_TRUE;
    ctx->insert_query = pgsql_build_insert_query("\"fluentbit\"", FLB_FALSE);

    TEST_CHECK(ctx->insert_query != NULL);

    return ctx->insert_query != NULL ? 0 : -1;
}

static void pgsql_test_context_destroy(struct flb_pgsql_config *ctx)
{
    if (ctx->insert_query != NULL) {
        flb_sds_destroy(ctx->insert_query);
        ctx->insert_query = NULL;
    }
}

static int pgsql_test_create_log_chunk(struct flb_log_event_encoder *encoder,
                                       struct flb_event_chunk *chunk,
                                       int record_count)
{
    struct flb_time timestamp;
    flb_sds_t tag;
    int index;
    int result;

    result = flb_log_event_encoder_init(encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS);
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    for (index = 0; index < record_count; index++) {
        result = flb_log_event_encoder_begin_record(encoder);
        TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS);
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }

        flb_time_set(&timestamp, 1700000000 + index, 500000000);

        result = flb_log_event_encoder_set_timestamp(encoder, &timestamp);
        TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS);
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }

        result = flb_log_event_encoder_append_body_values(
                     encoder,
                     FLB_LOG_EVENT_CSTRING_VALUE("message"),
                     FLB_LOG_EVENT_CSTRING_VALUE("hello"),
                     FLB_LOG_EVENT_CSTRING_VALUE("value"),
                     FLB_LOG_EVENT_INT32_VALUE(index + 1));
        TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS);
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }

        result = flb_log_event_encoder_commit_record(encoder);
        TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS);
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }
    }

    tag = flb_sds_create("pgsql.test");
    TEST_CHECK(tag != NULL);
    if (tag == NULL) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    memset(chunk, 0, sizeof(struct flb_event_chunk));
    chunk->type = FLB_EVENT_TYPE_LOGS;
    chunk->tag = tag;
    chunk->data = encoder->output_buffer;
    chunk->size = encoder->output_length;
    chunk->total_events = record_count;

    return 0;
}

static void pgsql_test_destroy_log_chunk(struct flb_log_event_encoder *encoder,
                                         struct flb_event_chunk *chunk)
{
    if (chunk->tag != NULL) {
        flb_sds_destroy(chunk->tag);
        chunk->tag = NULL;
    }

    flb_log_event_encoder_destroy(encoder);
    chunk->data = NULL;
    chunk->size = 0;
}

static int pgsql_test_create_invalid_root_chunk(msgpack_sbuffer *sbuf,
                                                struct flb_event_chunk *chunk)
{
    msgpack_packer pck;
    flb_sds_t tag;

    msgpack_sbuffer_init(sbuf);
    msgpack_packer_init(&pck, sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "root", 4);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "bad", 3);

    tag = flb_sds_create("pgsql.invalid");
    TEST_CHECK(tag != NULL);
    if (tag == NULL) {
        msgpack_sbuffer_destroy(sbuf);
        return -1;
    }

    memset(chunk, 0, sizeof(struct flb_event_chunk));
    chunk->type = FLB_EVENT_TYPE_LOGS;
    chunk->tag = tag;
    chunk->data = sbuf->data;
    chunk->size = sbuf->size;
    chunk->total_events = 1;

    return 0;
}

static void pgsql_test_destroy_invalid_root_chunk(msgpack_sbuffer *sbuf,
                                                  struct flb_event_chunk *chunk)
{
    if (chunk->tag != NULL) {
        flb_sds_destroy(chunk->tag);
        chunk->tag = NULL;
    }

    msgpack_sbuffer_destroy(sbuf);
    chunk->data = NULL;
    chunk->size = 0;
}

static int pgsql_test_invoke_flush(struct flb_event_chunk *event_chunk,
                                   struct flb_pgsql_config *ctx,
                                   struct flb_config *config)
{
    struct flb_output_flush out_flush;

    memset(&out_flush, 0, sizeof(out_flush));
    pgsql_test_flush_result = 123456;

    cb_pgsql_flush(event_chunk, &out_flush, NULL, ctx, config);

    return pgsql_test_flush_result;
}

void test_pgsql_build_insert_query_postgres(void)
{
    flb_sds_t query;

    query = pgsql_build_insert_query("\"fluentbit\"", FLB_FALSE);
    TEST_CHECK(query != NULL);

    if (query != NULL) {
        TEST_CHECK(strcmp(query,
                          "INSERT INTO \"fluentbit\" (tag, time, data) VALUES ($1, "
                          "to_timestamp($2::double precision), $3::jsonb);") == 0);
        flb_sds_destroy(query);
    }
}

void test_pgsql_build_insert_query_cockroach(void)
{
    flb_sds_t query;

    query = pgsql_build_insert_query("\"fluentbit\"", FLB_TRUE);
    TEST_CHECK(query != NULL);

    if (query != NULL) {
        TEST_CHECK(strcmp(query,
                          "INSERT INTO \"fluentbit\" (tag, time, data) VALUES ($1, "
                          "DATE '1970-01-01' + ($2::float8 * INTERVAL '1 second'), "
                          "$3::jsonb);") == 0);
        flb_sds_destroy(query);
    }
}

void test_pgsql_format_timestamp(void)
{
    struct flb_time timestamp;
    char buffer[64];
    int result;

    flb_time_set(&timestamp, 1700000000, 500000000);

    result = pgsql_format_timestamp(buffer, sizeof(buffer), &timestamp);

    TEST_CHECK(result > 0);
    TEST_CHECK(strcmp(buffer, "1700000000.500000000") == 0);
}

void test_pgsql_format_body_json(void)
{
    msgpack_sbuffer sbuf;
    msgpack_unpacked unpacked;
    msgpack_object *body;
    char *json;

    body = NULL;
    pack_test_body(&sbuf, &unpacked, &body);
    TEST_CHECK(body != NULL);

    if (body == NULL) {
        msgpack_unpacked_destroy(&unpacked);
        msgpack_sbuffer_destroy(&sbuf);
        return;
    }

    json = pgsql_format_body_json(body, FLB_TRUE);
    TEST_CHECK(json != NULL);

    if (json != NULL) {
        TEST_CHECK(strcmp(json, "{\"message\":\"hello\",\"value\":1}") == 0);
        pgsql_free_body_json(json);
    }

    msgpack_unpacked_destroy(&unpacked);
    msgpack_sbuffer_destroy(&sbuf);
}

void test_pgsql_format_body_json_cleanup_contract(void)
{
    msgpack_sbuffer sbuf;
    msgpack_unpacked unpacked;
    msgpack_object *body;
    char *json;
    int index;

    body = NULL;
    pack_test_body(&sbuf, &unpacked, &body);
    TEST_CHECK(body != NULL);

    if (body == NULL) {
        msgpack_unpacked_destroy(&unpacked);
        msgpack_sbuffer_destroy(&sbuf);
        return;
    }

    for (index = 0; index < 32; index++) {
        json = pgsql_format_body_json(body, FLB_TRUE);
        TEST_CHECK(json != NULL);

        if (json != NULL) {
            TEST_CHECK(strcmp(json, "{\"message\":\"hello\",\"value\":1}") == 0);
            pgsql_free_body_json(json);
        }
    }

    pgsql_free_body_json(NULL);

    msgpack_unpacked_destroy(&unpacked);
    msgpack_sbuffer_destroy(&sbuf);
}

void test_pgsql_translate_decoder_result(void)
{
    TEST_CHECK(pgsql_translate_decoder_result(FLB_EVENT_DECODER_SUCCESS) == FLB_OK);
    TEST_CHECK(pgsql_translate_decoder_result(
                   FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA) == FLB_RETRY);
    TEST_CHECK(pgsql_translate_decoder_result(
                   FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE) == FLB_ERROR);
}

void test_pgsql_conn_status_string(void)
{
    TEST_CHECK(strcmp(pgsql_conn_status_string(CONNECTION_OK),
                      "CONNECTION_OK") == 0);
    TEST_CHECK(strcmp(pgsql_conn_status_string(CONNECTION_BAD),
                      "CONNECTION_BAD") == 0);
    TEST_CHECK(strcmp(pgsql_conn_status_string((ConnStatusType) -1),
                      "CONNECTION_UNKNOWN") == 0);
}

void test_pgsql_next_connection_without_connection_fails(void)
{
    struct flb_pgsql_config ctx;
    struct flb_output_instance ins;
    struct flb_output_plugin plugin;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ins, 0, sizeof(ins));
    memset(&plugin, 0, sizeof(plugin));

    plugin.name = "pgsql";
    ins.p = &plugin;
    ins.log_level = FLB_LOG_OFF;
    ctx.ins = &ins;

    TEST_CHECK(pgsql_next_connection(&ctx) == -1);
}

void test_pgsql_destroy_connections_null_safe(void)
{
    struct flb_pgsql_config ctx;

    memset(&ctx, 0, sizeof(ctx));

    pgsql_destroy_connections(&ctx);
    TEST_CHECK(ctx.conn_current == NULL);
}

void test_pgsql_create_connection_null_handle_fails(void)
{
    struct flb_pgsql_config ctx;
    struct flb_output_instance ins;
    struct flb_output_plugin plugin;
    PGconn *conn;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ins, 0, sizeof(ins));
    memset(&plugin, 0, sizeof(plugin));

    plugin.name = "pgsql";
    ins.p = &plugin;
    ins.log_level = FLB_LOG_OFF;
    ctx.ins = &ins;

    pgsql_test_libpq_reset();
    pgsql_test_libpq_state.pqsetdb_return_null = FLB_TRUE;

    conn = pgsql_create_connection(&ctx);

    TEST_CHECK(conn == NULL);
    TEST_CHECK(pgsql_test_libpq_state.pqsetdb_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.pqfinish_calls == 0);
}

void test_cb_pgsql_flush_without_connection_retries(void)
{
    struct flb_pgsql_config ctx;
    struct flb_output_instance ins;
    struct flb_output_plugin plugin;
    struct flb_log_event_encoder encoder;
    struct flb_event_chunk chunk;
    struct flb_config config;
    int result;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ins, 0, sizeof(ins));
    memset(&plugin, 0, sizeof(plugin));
    memset(&config, 0, sizeof(config));

    plugin.name = "pgsql";
    ins.p = &plugin;
    ins.log_level = FLB_LOG_OFF;
    ctx.ins = &ins;

    result = pgsql_test_create_log_chunk(&encoder, &chunk, 1);
    TEST_CHECK(result == 0);
    if (result != 0) {
        return;
    }

    pgsql_test_libpq_reset();

    result = pgsql_test_invoke_flush(&chunk, &ctx, &config);
    TEST_CHECK(result == FLB_RETRY);
    TEST_CHECK(pgsql_test_libpq_state.begin_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.active_results == 0);

    pgsql_test_destroy_log_chunk(&encoder, &chunk);
}

void test_cb_pgsql_flush_mid_batch_insert_failure_retries_and_recovers(void)
{
    struct flb_pgsql_config ctx;
    struct flb_output_instance ins;
    struct flb_output_plugin plugin;
    struct pg_conn conn;
    struct flb_log_event_encoder encoder;
    struct flb_event_chunk chunk;
    struct flb_config config;
    int result;

    memset(&config, 0, sizeof(config));

    pgsql_test_libpq_reset();

    result = pgsql_test_context_init(&ctx, &ins, &plugin, &conn);
    TEST_CHECK(result == 0);
    if (result != 0) {
        return;
    }

    result = pgsql_test_create_log_chunk(&encoder, &chunk, 2);
    TEST_CHECK(result == 0);
    if (result != 0) {
        pgsql_test_context_destroy(&ctx);
        return;
    }

    pgsql_test_libpq_state.insert_failure_call = 2;

    result = pgsql_test_invoke_flush(&chunk, &ctx, &config);
    TEST_CHECK(result == FLB_RETRY);
    TEST_CHECK(pgsql_test_libpq_state.begin_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.commit_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.rollback_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.pqexec_prepared_calls == 2);
    TEST_CHECK(pgsql_test_libpq_state.pqprepare_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.pqreset_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.active_results == 0);
    TEST_CHECK(conn.status == CONNECTION_BAD);

    /* Recovery is attempted on the next flush once libpq reports BAD. */
    pgsql_test_libpq_state.insert_failure_call = 0;

    result = pgsql_test_invoke_flush(&chunk, &ctx, &config);
    TEST_CHECK(result == FLB_OK);
    TEST_CHECK(pgsql_test_libpq_state.begin_calls == 2);
    TEST_CHECK(pgsql_test_libpq_state.commit_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.rollback_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.pqexec_prepared_calls == 4);
    TEST_CHECK(pgsql_test_libpq_state.pqprepare_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.pqreset_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.active_results == 0);
    TEST_CHECK(ctx.insert_statement_prepared == FLB_TRUE);
    TEST_CHECK(conn.status == CONNECTION_OK);

    pgsql_test_destroy_log_chunk(&encoder, &chunk);
    pgsql_test_context_destroy(&ctx);
}

void test_cb_pgsql_flush_decoder_terminal_error_rolls_back(void)
{
    struct flb_pgsql_config ctx;
    struct flb_output_instance ins;
    struct flb_output_plugin plugin;
    struct pg_conn conn;
    struct flb_event_chunk chunk;
    struct flb_config config;
    msgpack_sbuffer sbuf;
    int result;

    memset(&config, 0, sizeof(config));

    pgsql_test_libpq_reset();

    result = pgsql_test_context_init(&ctx, &ins, &plugin, &conn);
    TEST_CHECK(result == 0);
    if (result != 0) {
        return;
    }

    result = pgsql_test_create_invalid_root_chunk(&sbuf, &chunk);
    TEST_CHECK(result == 0);
    if (result != 0) {
        pgsql_test_context_destroy(&ctx);
        return;
    }

    result = pgsql_test_invoke_flush(&chunk, &ctx, &config);
    TEST_CHECK(result == FLB_ERROR);
    TEST_CHECK(pgsql_test_libpq_state.begin_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.commit_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.rollback_calls == 1);
    TEST_CHECK(pgsql_test_libpq_state.pqexec_prepared_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.active_results == 0);

    pgsql_test_destroy_invalid_root_chunk(&sbuf, &chunk);
    pgsql_test_context_destroy(&ctx);
}

void test_cb_pgsql_flush_decoder_init_terminal_error_returns_error(void)
{
    struct flb_pgsql_config ctx;
    struct flb_output_instance ins;
    struct flb_output_plugin plugin;
    struct pg_conn conn;
    struct flb_event_chunk chunk;
    struct flb_config config;
    struct flb_log_event_encoder encoder;
    int result;

    memset(&config, 0, sizeof(config));

    pgsql_test_libpq_reset();

    result = pgsql_test_context_init(&ctx, &ins, &plugin, &conn);
    TEST_CHECK(result == 0);
    if (result != 0) {
        return;
    }

    result = pgsql_test_create_log_chunk(&encoder, &chunk, 1);
    TEST_CHECK(result == 0);
    if (result != 0) {
        pgsql_test_context_destroy(&ctx);
        return;
    }

    pgsql_test_libpq_state.decoder_init_result =
        FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE;

    result = pgsql_test_invoke_flush(&chunk, &ctx, &config);

    TEST_CHECK(result == FLB_ERROR);
    TEST_CHECK(pgsql_test_libpq_state.begin_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.commit_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.rollback_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.pqexec_prepared_calls == 0);
    TEST_CHECK(pgsql_test_libpq_state.active_results == 0);

    pgsql_test_destroy_log_chunk(&encoder, &chunk);
    pgsql_test_context_destroy(&ctx);
}

TEST_LIST = {
    {"build_insert_query_postgres", test_pgsql_build_insert_query_postgres},
    {"build_insert_query_cockroach", test_pgsql_build_insert_query_cockroach},
    {"format_timestamp", test_pgsql_format_timestamp},
    {"format_body_json", test_pgsql_format_body_json},
    {"format_body_json_cleanup_contract", test_pgsql_format_body_json_cleanup_contract},
    {"translate_decoder_result", test_pgsql_translate_decoder_result},
    {"conn_status_string", test_pgsql_conn_status_string},
    {"next_connection_without_connection_fails", test_pgsql_next_connection_without_connection_fails},
    {"destroy_connections_null_safe", test_pgsql_destroy_connections_null_safe},
    {"create_connection_null_handle_fails",
     test_pgsql_create_connection_null_handle_fails},
    {"cb_pgsql_flush_without_connection_retries",
     test_cb_pgsql_flush_without_connection_retries},
    {"cb_pgsql_flush_mid_batch_insert_failure_retries_and_recovers",
     test_cb_pgsql_flush_mid_batch_insert_failure_retries_and_recovers},
    {"cb_pgsql_flush_decoder_terminal_error_rolls_back",
     test_cb_pgsql_flush_decoder_terminal_error_rolls_back},
    {"cb_pgsql_flush_decoder_init_terminal_error_returns_error",
     test_cb_pgsql_flush_decoder_init_terminal_error_returns_error},
    {0}
};
