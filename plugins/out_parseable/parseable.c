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

        /* 
         * Pack an empty map of original size + 1 because we are appending one 
         * additional keyval pair later
         */
        msgpack_pack_map(&pk, p->via.map.size + 1);

        /* Pack the original keyval pairs in first */
        for (int i = 0; i < p->via.map.size; i++) {
            msgpack_pack_object(&pk, p->via.map.ptr[i].key);
            msgpack_pack_object(&pk, p->via.map.ptr[i].val);
        }

        /* Append one more keyval pair to this log */
        msgpack_pack_str_with_body(&pk, "source", 6);
        msgpack_pack_str_with_body(&pk, "fluent bit parseable plugin", 25);

        /* Convert from msgpack serialization to JSON serialization for sending through HTTP */
        body = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);

        /* Free up buffer as we don't need it anymore */
        msgpack_sbuffer_destroy(&sbuf);

        /* Get upstream connection */
        u_conn = flb_upstream_conn_get(ctx->upstream);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "connection initialization error");
            flb_sds_destroy(body);
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Compose HTTP Client request */
        client = flb_http_client(u_conn,
                                 FLB_HTTP_POST, "/api/v1/logstream/random",
                                 body, flb_sds_len(body),
                                 ctx->server_host, ctx->server_port,
                                 NULL, 0);

        if (!client) {
            flb_plg_error(ctx->ins, "could not create HTTP client");
            flb_sds_destroy(body);
            flb_upstream_conn_release(u_conn);
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        flb_http_add_header(client, "Content-Type", 12, "application/json", 16);

        /* Perform request */
        ret = flb_http_do(client, &b_sent);
        flb_plg_info(ctx->ins, "HTTP request http_do=%i, HTTP Status: %i",
                     ret, client->resp.status);
                        
        /* Free up resources */
        flb_sds_destroy(body);
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
     FLB_CONFIG_MAP_STR, "server_host", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_host),
    "The host of the server to send logs to."
    },
    {
     FLB_CONFIG_MAP_INT, "server_port", 0,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_port),
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
