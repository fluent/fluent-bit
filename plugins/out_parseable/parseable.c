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
                                        FLB_IO_TCP | FLB_IO_ASYNC,
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
    struct flb_record_accessor *ra = NULL;
    struct flb_record_accessor *ns_ra = NULL;  // For checking namespace
    struct cfl_list *head;
    struct flb_slist_entry *entry;
    int skip = 0;
    (void) config;
    struct flb_http_client *client;
    struct flb_connection *u_conn;
    flb_sds_t body;
    flb_sds_t x_p_stream_value = NULL;
    int ret;
    int i;
    size_t b_sent;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    flb_sds_t current_ns = flb_ra_translate(ns_ra, NULL, -1, *log_event.body, NULL);
    flb_sds_t ns = flb_ra_translate(ra, NULL, -1, *log_event.body, NULL);


    /* Initialize event decoder */
    flb_plg_info(ctx->ins, "Initializing event decoder...");
    ret = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Failed to initialize event decoder");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Create record accessor if stream is set to $NAMESPACE */
    if (ctx->stream != NULL && strcmp(ctx->stream, "$NAMESPACE") == 0) {
        ra = flb_ra_create("$kubernetes['namespace_name']", FLB_TRUE);
        if (ra == NULL) {
            flb_plg_error(ctx->ins, "Failed to create record accessor");
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Create record accessor for namespace exclusion check */
    if (ctx->exclude_namespaces != NULL) {
        ns_ra = flb_ra_create("$kubernetes['namespace_name']", FLB_TRUE);
        if (ns_ra == NULL) {
            flb_plg_error(ctx->ins, "Failed to create namespace record accessor");
            if (ra != NULL) {
                flb_ra_destroy(ra);
            }
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Process each event */
    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        /* Check if namespace is in exclusion list */
       if (ns_ra != NULL && ctx->exclude_namespaces != NULL) {
            if (current_ns != NULL) {
                cfl_list_foreach(head, ctx->exclude_namespaces) {
                    entry = cfl_list_entry(head, struct flb_slist_entry, _head);
                    if (strcmp(current_ns, entry->str) == 0) {
                        flb_plg_debug(ctx->ins, "Skipping excluded namespace: %s", current_ns);
                        skip = FLB_TRUE;
                        break;
                    }
                }

                flb_sds_destroy(current_ns);
                if (skip) {
                    continue;
                }
            }
        }

        /* Initialize the packer and buffer */
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

        /* Pack the map with one additional field */
        msgpack_pack_map(&pk, log_event.body->via.map.size + 1);

        /* Pack original map content */
        for (i = 0; i < log_event.body->via.map.size; i++) {
            msgpack_pack_object(&pk, log_event.body->via.map.ptr[i].key);
            msgpack_pack_object(&pk, log_event.body->via.map.ptr[i].val);
        }

        /* Add source field */
        msgpack_pack_str_with_body(&pk, "source", 6);
        msgpack_pack_str_with_body(&pk, "fluent bit parseable plugin", 25);

        /* Convert to JSON */
        body = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);
        msgpack_sbuffer_destroy(&sbuf);  // Clean up the msgpack buffer immediately after conversion
        if (body == NULL) {
            flb_plg_error(ctx->ins, "Failed to convert msgpack to JSON");
            if (ra != NULL) {
                flb_ra_destroy(ra);
            }
            if (ns_ra != NULL) {
                flb_ra_destroy(ns_ra);
            }
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Determine X-P-Stream value */
        if (ra != NULL) {
            /* Use record accessor to get namespace_name */
            if (ns == NULL) {
                flb_plg_error(ctx->ins, "Failed to extract namespace_name using record accessor");
                flb_sds_destroy(body);
                msgpack_sbuffer_destroy(&sbuf);
                flb_ra_destroy(ra);
                if (ns_ra != NULL) {
                    flb_ra_destroy(ns_ra);
                }
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            x_p_stream_value = ns;
        }
        else if (ctx->stream != NULL) {
            x_p_stream_value = flb_sds_create(ctx->stream);
            if (x_p_stream_value == NULL) {
                flb_plg_error(ctx->ins, "Failed to set X-P-Stream header");
                flb_sds_destroy(body);
                msgpack_sbuffer_destroy(&sbuf);
                if (ra != NULL) {
                    flb_ra_destroy(ra);
                }
                if (ns_ra != NULL) {
                    flb_ra_destroy(ns_ra);
                }
                flb_log_event_decoder_destroy(&log_decoder);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
        }
        else {
            flb_plg_error(ctx->ins, "Stream is not set");
            flb_sds_destroy(body);
            msgpack_sbuffer_destroy(&sbuf);
            if (ra != NULL) {
                flb_ra_destroy(ra);
            }
            if (ns_ra != NULL) {
                flb_ra_destroy(ns_ra);
            }
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Get upstream connection */
        u_conn = flb_upstream_conn_get(ctx->upstream);
        if (u_conn == NULL) {
            flb_plg_error(ctx->ins, "Connection initialization error");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            msgpack_sbuffer_destroy(&sbuf);
            if (ra != NULL) {
                flb_ra_destroy(ra);
            }
            if (ns_ra != NULL) {
                flb_ra_destroy(ns_ra);
            }
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Create HTTP client */
        client = flb_http_client(u_conn,
                               FLB_HTTP_POST, "/api/v1/ingest",
                               body, flb_sds_len(body),
                               ctx->server_host, ctx->server_port,
                               NULL, 0);
        if (client == NULL) {
            flb_plg_error(ctx->ins, "Could not create HTTP client");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            msgpack_sbuffer_destroy(&sbuf);
            flb_upstream_conn_release(u_conn);
            if (ra != NULL) {
                flb_ra_destroy(ra);
            }
            if (ns_ra != NULL) {
                flb_ra_destroy(ns_ra);
            }
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Set headers */
        flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
        flb_http_add_header(client, "X-P-Stream", 10, x_p_stream_value, flb_sds_len(x_p_stream_value));
        flb_http_basic_auth(client, ctx->username, ctx->password);


        /* Perform request */
        ret = flb_http_do(client, &b_sent);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "HTTP request failed");
            flb_sds_destroy(body);
            flb_sds_destroy(x_p_stream_value);
            flb_http_client_destroy(client);
            flb_upstream_conn_release(u_conn);
            msgpack_sbuffer_destroy(&sbuf);
            continue;  // Skip to next event instead of returning error
        }
        flb_plg_info(ctx->ins, "HTTP request sent. Status=%i", client->resp.status);

        /* Clean up resources for this iteration */
        flb_sds_destroy(body);
        flb_sds_destroy(x_p_stream_value);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(u_conn);
        msgpack_sbuffer_destroy(&sbuf);
    }

    /* Final cleanup */
    if (ra != NULL) {
        flb_ra_destroy(ra);
    }
    if (ns_ra != NULL) {
        flb_ra_destroy(ns_ra);
    }
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
     FLB_CONFIG_MAP_INT, "server_port", "443",  // Default port is 443 for HTTPS
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_port),
    "The port on the host to send logs to."
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
     FLB_CONFIG_MAP_CLIST, "Exclude_Namespaces", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, exclude_namespaces),
    "A space-separated list of Kubernetes namespaces to exclude from log forwarding."
    },
    {
     FLB_CONFIG_MAP_INT, "connect_timeout", "600",  // Default to 600 seconds
     0, FLB_TRUE, offsetof(struct flb_out_parseable, connect_timeout),
    "Timeout in seconds for establishing connections."
    },
    {
     FLB_CONFIG_MAP_INT, "accept_timeout", "600",  // Default to 600 seconds
     0, FLB_TRUE, offsetof(struct flb_out_parseable, accept_timeout),
    "Timeout in seconds for accepting connections."
    },
    {
     FLB_CONFIG_MAP_INT, "retry_limit", "5",  // Default to 5 retries
     0, FLB_TRUE, offsetof(struct flb_out_parseable, retry_limit),
    "Maximum number of retries for sending logs."
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
