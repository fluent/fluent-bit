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
    (void) config;
    struct flb_http_client *client;
    struct flb_connection *u_conn;
    flb_sds_t body;
    flb_sds_t x_p_stream_value = NULL;
    int ret;
    size_t b_sent;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    int i;
    struct flb_record_accessor *ra = NULL;

    /* Initialize record accessor if using $NAMESPACE */
    if (ctx->stream && strcmp(ctx->stream, "$NAMESPACE") == 0) {
        ra = flb_ra_create("$record['namespace_name']", FLB_TRUE);
        if (!ra) {
            flb_plg_error(ctx->ins, "failed to create record accessor");
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data,
                                    event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "failed to initialize event decoder");
        if (ra) {
            flb_ra_destroy(ra);
        }
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        /* Only operate if log is map type */
        if (log_event.body->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* Initialize the packer and buffer for serialization/packing */
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

        /* Pack original key-value pairs */
        msgpack_pack_map(&pk, log_event.body->via.map.size + 1);
        for (i = 0; i < log_event.body->via.map.size; i++) {
            msgpack_pack_object(&pk, log_event.body->via.map.ptr[i].key);
            msgpack_pack_object(&pk, log_event.body->via.map.ptr[i].val);
        }


        /* Append one more key-value pair */
        msgpack_pack_str_with_body(&pk, "source", 6);
        msgpack_pack_str_with_body(&pk, "fluent bit parseable plugin", 25);

        /* Convert from msgpack to JSON */
        body = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);

        /* Free up buffer as we don't need it anymore */
        msgpack_sbuffer_destroy(&sbuf);

        /* Determine the value of the X-P-Stream header */
        if (ctx->stream && strcmp(ctx->stream, "$NAMESPACE") == 0) {
            flb_sds_t namespace_name;
            
            /* Get namespace using record accessor */
            flb_plg_debug(ctx->ins, "Record body: %s", body);
            
            /* Debug: Print map size and contents */
            flb_plg_debug(ctx->ins, "Map size: %d", log_event.body->via.map.size);
            for (i = 0; i < log_event.body->via.map.size; i++) {
                msgpack_object *k = &log_event.body->via.map.ptr[i].key;
                msgpack_object *v = &log_event.body->via.map.ptr[i].val;
                
                if (k->type == MSGPACK_OBJECT_STR) {
                    flb_plg_debug(ctx->ins, "Key: %.*s", (int)k->via.str.size, k->via.str.ptr);
                }
            }

            flb_plg_debug(ctx->ins, "Using record accessor pattern: %s", 
                         flb_ra_get_pattern(ra));

            namespace_name = flb_ra_translate(ra, NULL, -1, *log_event.body, NULL);

            /* Check excluded namespaces */
            if (ctx->exclude_namespaces) {
                struct mk_list *head;
                struct flb_slist_entry *entry;

                mk_list_foreach(head, ctx->exclude_namespaces) {
                    entry = mk_list_entry(head, struct flb_slist_entry, _head);
                    flb_plg_debug(ctx->ins, "Checking against exclude namespace: %s", entry->str);
                    if (flb_sds_cmp(entry->str, namespace_name, flb_sds_len(namespace_name)) == 0) {
                        flb_plg_debug(ctx->ins, "Skipping excluded namespace: %s", namespace_name);
                        flb_sds_destroy(namespace_name);
                        flb_sds_destroy(body);
                        goto skip_record;
                    }
                }
            }

            x_p_stream_value = namespace_name;
        }
        else if (ctx->stream) {
            /* Use the user-specified stream directly */
            x_p_stream_value = flb_sds_create(ctx->stream);
            if (!x_p_stream_value) {
                flb_plg_error(ctx->ins, "Failed to set X-P-Stream header to the specified stream: %s", ctx->stream);
                flb_sds_destroy(body);
                continue;
            }
        }
        else {
            flb_plg_error(ctx->ins, "Stream is not set. Cannot determine the value for X-P-Stream.");
            flb_sds_destroy(body);
            continue;
        }

        flb_plg_debug(ctx->ins, "Creating upstream with server: %s, port: %d", ctx->server_host, ctx->server_port);

        /* Get upstream connection */
        u_conn = flb_upstream_conn_get(ctx->upstream);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "connection initialization error");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            continue;
        }

        /* Compose HTTP Client request */
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
            continue;
        }

        /* Add HTTP headers */
        flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
        flb_http_add_header(client, "X-P-Stream", 10, x_p_stream_value, flb_sds_len(x_p_stream_value));
        flb_http_basic_auth(client, ctx->username, ctx->password);

        /* Perform request */
        ret = flb_http_do(client, &b_sent);
        flb_plg_debug(ctx->ins, "HTTP request http_do=%i, HTTP Status: %i",
                     ret, client->resp.status);

        /* Clean up resources */
        flb_sds_destroy(body);
        flb_sds_destroy(x_p_stream_value);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);

skip_record:
        continue;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    if (ra) {
        flb_ra_destroy(ra);
    }
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
