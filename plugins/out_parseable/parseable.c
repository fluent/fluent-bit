#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_metrics.h>


#include <msgpack.h>
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

    ctx->upstream = flb_upstream_create(config,
                                        ctx->p_server,
                                        ctx->p_port,
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

static void cb_parseable_flush(struct flb_event_chunk *event_chunk,
                               struct flb_output_flush *out_flush,
                               struct flb_input_instance *i_ins,
                               void *out_context,
                               struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    struct flb_out_parseable *ctx = out_context;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    struct flb_http_client *client;
    struct flb_connection *u_conn;
    flb_sds_t body;
    flb_sds_t x_p_stream_value = NULL;
    int ret;
    size_t b_sent;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result,
                               event_chunk->data,
                               event_chunk->size, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_time_pop_from_msgpack(&tmp, &result, &p);

        /* Only operate if log is map type */
        if (p->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* Initialize the packer and buffer for serialization/packing */
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

        /* Pack original key-value pairs */
        msgpack_pack_map(&pk, p->via.map.size + 1);
        for (int i = 0; i < p->via.map.size; i++) {
            msgpack_pack_object(&pk, p->via.map.ptr[i].key);
            msgpack_pack_object(&pk, p->via.map.ptr[i].val);
        }

        /* Append one more key-value pair */
        msgpack_pack_str_with_body(&pk, "source", 6);
        msgpack_pack_str_with_body(&pk, "fluent bit parseable plugin", 25);

        /* Convert from msgpack to JSON */
        body = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);
        // flb_plg_info(ctx->ins, "Body content: %s", body);

        /* Free up buffer as we don't need it anymore */
        msgpack_sbuffer_destroy(&sbuf);

        /* Determine the value of the X-P-Stream header */
        if (ctx->p_stream && strcmp(ctx->p_stream, "$NAMESPACE") == 0) {
            /* Extract namespace_name from the body */
            flb_sds_t body_copy = flb_sds_create(body);
            if (body_copy == NULL) {
                flb_plg_error(ctx->ins, "Failed to create a copy of the body");
                flb_sds_destroy(body);
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            flb_sds_t namespace_name = flb_sds_create_size(256); // Dynamic string
            if (body_copy != NULL) {
                char *namespace_name_value = strstr(body_copy, "\"namespace_name\":\"");
                if (namespace_name_value != NULL) {
                    namespace_name_value += strlen("\"namespace_name\":\"");
                    char *end_quote = strchr(namespace_name_value, '\"');
                    if (end_quote != NULL) {
                        *end_quote = '\0';  // Null-terminate the extracted value
                        namespace_name = flb_sds_printf(&namespace_name, "%s", namespace_name_value);
                        // flb_plg_info(ctx->ins, "Namespace name extracted value: %s", namespace_name_value);
                    }
                }
            }
            flb_sds_destroy(body_copy);

            if (!namespace_name || flb_sds_len(namespace_name) == 0) {
                flb_plg_error(ctx->ins, "Failed to extract namespace_name from the body");
                flb_sds_destroy(body);
                flb_sds_destroy(namespace_name);
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            x_p_stream_value = namespace_name;
        }
        else if (ctx->p_stream) {
            /* Use the user-specified stream directly */
            x_p_stream_value = flb_sds_create(ctx->p_stream);
            if (!x_p_stream_value) {
                flb_plg_error(ctx->ins, "Failed to set X-P-Stream header to the specified stream: %s", ctx->p_stream);
                flb_sds_destroy(body);
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
        }
        else {
            flb_plg_error(ctx->ins, "P_Stream is not set. Cannot determine the value for X-P-Stream.");
            flb_sds_destroy(body);
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Get upstream connection */
        u_conn = flb_upstream_conn_get(ctx->upstream);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "connection initialization error");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Compose HTTP Client request */
        client = flb_http_client(u_conn,
                                 FLB_HTTP_POST, "/api/v1/ingest",
                                 body, flb_sds_len(body),
                                 ctx->p_server, ctx->p_port,
                                 NULL, 0);

        if (!client) {
            flb_plg_error(ctx->ins, "could not create HTTP client");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            flb_upstream_conn_release(u_conn);
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Add HTTP headers */
        flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
        flb_http_add_header(client, "X-P-Stream", 10, x_p_stream_value, flb_sds_len(x_p_stream_value));
        flb_http_basic_auth(client, ctx->p_username, ctx->p_password);

        /* Perform request */
        ret = flb_http_do(client, &b_sent);
        flb_plg_info(ctx->ins, "HTTP request http_do=%i, HTTP Status: %i",
                     ret, client->resp.status);

        /* Clean up resources */
        flb_sds_destroy(body);
        flb_sds_destroy(x_p_stream_value);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
    }
    msgpack_unpacked_destroy(&result);

    FLB_OUTPUT_RETURN(FLB_OK);
}


static int cb_parseable_exit(void *data, struct flb_config *config)
{
    struct flb_out_parseable *ctx = data;

    if (!ctx) {
        return 0;
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
     FLB_CONFIG_MAP_STR, "P_Server", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, p_server),
    "The host of the server to send logs to."
    },
    {
     FLB_CONFIG_MAP_STR, "P_Username", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, p_username),
    "The parseable server username."
    },
    {
     FLB_CONFIG_MAP_STR, "P_Password", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, p_password),
    "The parseable server password."
    },
    {
     FLB_CONFIG_MAP_STR, "P_Stream", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, p_stream),
    "The stream name to send logs to. using $NAMESPACE will dynamically create namespace."
    },
    {
     FLB_CONFIG_MAP_INT, "P_Port", 0,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, p_port),
    "The port on the host to send logs to."
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
