#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_record_accessor.h>


#include "parseable.h"

static int cb_parseable_init(struct flb_output_instance *ins,
                             struct flb_config *config, void *data)
{
    int ret;
    struct flb_out_parseable *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_parseable));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* Read in config values */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "Configured port: %d", ctx->server_port);

    ctx->upstream = flb_upstream_create(config,
                                        ctx->server_host,
                                        ctx->server_port,
                                        FLB_IO_TCP,
                                        NULL);

    if (!ctx->upstream) {
        flb_free(ctx);
        return -1;
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

/* Function to extract namespace_name using Fluent Bit record accessor API */
static flb_sds_t cb_get_namespace_name(struct flb_out_parseable *ctx, struct flb_log_event *log_event)
{
    flb_sds_t namespace_name = NULL;
    struct flb_record_accessor *ra_namespace;
    flb_sds_t str_val = NULL;
    int len = -1;

    /* Create a record accessor for namespace_name */
    ra_namespace = flb_ra_create("$kubernetes['namespace_name']", FLB_TRUE);
    if (!ra_namespace) {
        flb_plg_error(ctx->ins, "failed to create record accessor for namespace_name");
        return NULL;
    }

    /* Check if metadata is accessible */
    if (!log_event->metadata || log_event->metadata->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "log event metadata is not a map or is NULL");
        flb_ra_destroy(ra_namespace);
        return NULL;
    }

    /* Get the value using the record accessor */
    str_val = flb_ra_translate(ra_namespace, NULL, 0, *log_event->metadata, NULL);
    if (!str_val) {
        flb_plg_error(ctx->ins, "namespace_name not found in log event metadata");
        flb_ra_destroy(ra_namespace);
        return NULL;
    }

    /* Create an SDS string for namespace_name */
    namespace_name = flb_sds_create(str_val);
    if (!namespace_name) {
        flb_plg_error(ctx->ins, "failed to allocate memory for namespace_name");
        flb_sds_destroy(str_val);
        flb_ra_destroy(ra_namespace);
        return NULL;
    }

    /* Clean up */
    flb_sds_destroy(str_val);
    flb_ra_destroy(ra_namespace);

    return namespace_name;
}

/* Main flush callback */
static void cb_parseable_flush(struct flb_event_chunk *event_chunk,
                               struct flb_output_flush *out_flush,
                               struct flb_input_instance *i_ins,
                               void *out_context,
                               struct flb_config *config)
{
    struct flb_out_parseable *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_http_client *client;
    struct flb_connection *u_conn;
    flb_sds_t body;
    flb_sds_t x_p_stream_value = NULL;
    int ret;
    size_t b_sent;

    /* Initialize the log event decoder */
    if (flb_log_event_decoder_init(&log_decoder, (char *)event_chunk->data, event_chunk->size) != 0) {
        flb_plg_error(ctx->ins, "failed to initialize log event decoder");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        // /* Convert body to JSON */
        // if (log_event.body->type == MSGPACK_OBJECT_STR) {
        //     body = flb_sds_create_len(log_event.body->via.str.ptr, log_event.body->via.str.size);
        // } else if (log_event.body->type == MSGPACK_OBJECT_BIN) {
        //     body = flb_sds_create_len(log_event.body->via.bin.ptr, log_event.body->via.bin.size);
        // } else {
        //     flb_plg_error(ctx->ins, "unsupported log event body type: %d", log_event.body->type);
        //     flb_log_event_decoder_destroy(&log_decoder);
        //     FLB_OUTPUT_RETURN(FLB_ERROR);
        // }

        if (!body) {
            flb_plg_error(ctx->ins, "failed to convert log event body to JSON");
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Determine the value of the X-P-Stream header */
        if (ctx->stream && strcmp(ctx->stream, "$NAMESPACE") == 0) {
            x_p_stream_value = cb_get_namespace_name(ctx, &log_event);
            if (!x_p_stream_value) {
                flb_plg_error(ctx->ins, "failed to extract namespace_name");
                flb_sds_destroy(body);
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
        } else if (ctx->stream) {
            x_p_stream_value = flb_sds_create(ctx->stream);
            if (!x_p_stream_value) {
                flb_plg_error(ctx->ins, "failed to set X-P-Stream header to the specified stream: %s", ctx->stream);
                flb_sds_destroy(body);
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
        } else {
            flb_plg_error(ctx->ins, "Stream is not set. Cannot determine the value for X-P-Stream.");
            flb_sds_destroy(body);
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Get upstream connection */
        u_conn = flb_upstream_conn_get(ctx->upstream);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "connection initialization error");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Create HTTP client and send request */
        client = flb_http_client(u_conn,
                                 FLB_HTTP_POST, "/api/v1/ingest",
                                 body, flb_sds_len(body),
                                 ctx->server_host, ctx->server_port,
                                 NULL, 0);
        if (!client) {
            flb_plg_error(ctx->ins, "could not create HTTP client");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            flb_upstream_conn_release(u_conn);
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Add HTTP headers */
        flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
        flb_http_add_header(client, "X-P-Stream", 10, x_p_stream_value, flb_sds_len(x_p_stream_value));
        flb_http_basic_auth(client, ctx->username, ctx->password);

        /* Perform request */
        ret = flb_http_do(client, &b_sent);
        flb_plg_info(ctx->ins, "HTTP request http_do=%i, HTTP Status: %i", ret, client->resp.status);

        /* Clean up resources */
        flb_sds_destroy(body);
        flb_sds_destroy(x_p_stream_value);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
    }

    /* Destroy the log event decoder */
    flb_log_event_decoder_destroy(&log_decoder);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_parseable_exit(void *data, struct flb_config *config)
{
    struct flb_out_parseable *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->exclude_namespaces) {
        flb_slist_destroy((struct mk_list *)ctx->exclude_namespaces);
    }
    
    /* Free up resources */
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "server_host", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_host),
    "The host of the server to send logs to."
    },
    {
     FLB_CONFIG_MAP_STR, "username", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, username),
    "The parseable server username."
    },
    {
     FLB_CONFIG_MAP_STR, "password", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, password),
    "The parseable server password."
    },
    {
     FLB_CONFIG_MAP_STR, "stream", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, stream),
    "The stream name to send logs to. Using $NAMESPACE will dynamically create a namespace."
    },
    {
     FLB_CONFIG_MAP_INT, "server_port", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_port),
    "The port on the host to send logs to."
    },
    {
     FLB_CONFIG_MAP_CLIST, "Exclude_Namespaces", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, exclude_namespaces),
    "A space-separated list of Kubernetes namespaces to exclude from log forwarding."
    },
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_parseable_plugin = {
    .name         = "parseable",
    .description  = "Sends events to a HTTP server",
    .cb_init      = cb_parseable_init,
    .cb_flush     = cb_parseable_flush,
    .cb_exit      = cb_parseable_exit,
    .flags        = 0,
    .event_type   = FLB_OUTPUT_LOGS,
    .config_map   = config_map
};
