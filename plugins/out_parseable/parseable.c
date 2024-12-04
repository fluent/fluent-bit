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

    flb_plg_info(ctx->ins, "Configured port: %d", ctx->port);
    flb_plg_info(ctx->ins, "Configured server: %d", ctx->server);
    flb_plg_info(ctx->ins, "Configured username: %d", ctx->username);
    flb_plg_info(ctx->ins, "Configured password: %d", ctx->password);
    flb_plg_info(ctx->ins, "Configured exclude_namespaces: %d", ctx->exclude_namespaces);
    flb_plg_info(ctx->ins, "Configured stream: %d", ctx->stream);

    ctx->upstream = flb_upstream_create(config,
                                        ctx->server,
                                        ctx->port,
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

        /* Free up buffer as we don't need it anymore */
        msgpack_sbuffer_destroy(&sbuf);

        /* Determine the value of the X-P-Stream header */
        if (ctx->stream && strcmp(ctx->stream, "$NAMESPACE") == 0) {
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

                        // Debug: Print the extracted namespace name
                        flb_plg_info(ctx->ins, "Extracted namespace_name: %s", namespace_name);


                        struct mk_list *head;
                        struct flb_slist_entry *entry;

                        if (ctx->exclude_namespaces) {
                            mk_list_foreach(head, ctx->exclude_namespaces) {
                                entry = mk_list_entry(head, struct flb_slist_entry, _head);
                                flb_plg_info(ctx->ins, "Checking against exclude namespace: %s", entry->str);
                                // flb_plg_info(ctx->ins, "namespace_name: %s %d", namespace_name,flb_sds_len(namespace_name));
                                if (flb_sds_cmp(entry->str, namespace_name, flb_sds_len(namespace_name)) == 0) {
                                        flb_plg_info(ctx->ins, "Skipping excluded namespace: %s", namespace_name);
                                        // Cleanup
                                        flb_sds_destroy(namespace_name);
                                        flb_sds_destroy(body);
                                        flb_sds_destroy(body_copy);
                                        msgpack_unpacked_destroy(&result);
                                        
                                        // Skip sending the HTTP request
                                        FLB_OUTPUT_RETURN(FLB_OK);
                                }
                            }
                        }
                    }
                } else {
                    // Debug: Could not find the namespace_name in body_copy
                    flb_plg_info(ctx->ins, "namespace_name not found in body_copy.");
                }
            } else {
                // Debug: body_copy is NULL
                flb_plg_info(ctx->ins, "body_copy is NULL.");
            }

            flb_sds_destroy(body_copy);

            if (!namespace_name || flb_sds_len(namespace_name) == 0) {
                flb_plg_error(ctx->ins, "Failed to extract namespace_name from the body");
                flb_sds_destroy(body);
                flb_sds_destroy(namespace_name);
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            /* Determine the value of the X-P-Stream header */
            x_p_stream_value = namespace_name;  // Use the namespace name for the header
        }
        else if (ctx->stream) {
            /* Use the user-specified stream directly */
            x_p_stream_value = flb_sds_create(ctx->stream);
            if (!x_p_stream_value) {
                flb_plg_error(ctx->ins, "Failed to set X-P-Stream header to the specified stream: %s", ctx->stream);
                flb_sds_destroy(body);
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
        }
        else {
            flb_plg_error(ctx->ins, "Stream is not set. Cannot determine the value for X-P-Stream.");
            flb_sds_destroy(body);
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        flb_plg_info(ctx->ins, "Creating upstream with server: %s, port: %d", ctx->server, ctx->port);

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
                                 ctx->server, ctx->port,
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
        flb_http_basic_auth(client, ctx->username, ctx->password);

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

    flb_slist_destroy(&ctx->exclude_namespaces);
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
     FLB_CONFIG_MAP_STR, "Server", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server),
    "The host of the server to send logs to."
    },
    {
     FLB_CONFIG_MAP_STR, "Username", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, username),
    "The parseable server username."
    },
    {
     FLB_CONFIG_MAP_STR, "Password", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, password),
    "The parseable server password."
    },
    {
     FLB_CONFIG_MAP_STR, "Stream", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, stream),
    "The stream name to send logs to. Using $NAMESPACE will dynamically create a namespace."
    },
    {
     FLB_CONFIG_MAP_INT, "Port", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, port),
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
