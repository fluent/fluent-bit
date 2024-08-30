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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_kv.h>

#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_signv4.h>
#endif
#endif

#include "remote_write.h"
#include "remote_write_conf.h"

static int http_post(struct prometheus_remote_write_context *ctx,
                     const void *body, size_t body_len,
                     const char *tag, int tag_len)
{
    int ret;
    int out_ret = FLB_OK;
    struct flb_http_response *response;
    struct flb_http_request  *request;
    const char *compression_algorithm;
    char *additional_headers[3];

    if (strcasecmp(ctx->compression, "snappy") == 0) {
        compression_algorithm = "snappy";
    }
    else if (strcasecmp(ctx->compression, "gzip") == 0) {
        compression_algorithm = "gzip";
    }
    else {
        compression_algorithm = NULL;
    }

    additional_headers[0] = (char *) \
        FLB_PROMETHEUS_REMOTE_WRITE_VERSION_HEADER_NAME;
    additional_headers[1] = (char *) \
        FLB_PROMETHEUS_REMOTE_WRITE_VERSION_LITERAL;
    additional_headers[2] = NULL;

    request = flb_http_client_request_builder(
                    &ctx->http_client,
                    FLB_HTTP_CLIENT_ARGUMENT_METHOD(FLB_HTTP_POST),
                    FLB_HTTP_CLIENT_ARGUMENT_HOST(ctx->host),
                    FLB_HTTP_CLIENT_ARGUMENT_URI(ctx->uri),
                    FLB_HTTP_CLIENT_ARGUMENT_HEADERS(
                        FLB_HTTP_CLIENT_HEADER_ARRAY,
                        additional_headers),
                    FLB_HTTP_CLIENT_ARGUMENT_HEADERS(
                        FLB_HTTP_CLIENT_HEADER_CONFIG_MAP_LIST,
                        ctx->headers),
                    FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE(
                        FLB_PROMETHEUS_REMOTE_WRITE_MIME_PROTOBUF_LITERAL),
                    FLB_HTTP_CLIENT_ARGUMENT_BODY(body,
                                                  body_len,
                                                  compression_algorithm));

    if (request == NULL) {
        flb_plg_error(ctx->ins, "error initializing http request");

        return FLB_RETRY;
    }

    if (ctx->http_user != NULL &&
        ctx->http_passwd != NULL) {
        flb_http_request_set_authorization(request,
                                           HTTP_WWW_AUTHORIZATION_SCHEME_BASIC,
                                           ctx->http_user,
                                           ctx->http_passwd);
    }

    if (ctx->has_aws_auth) {
        ret = flb_http_request_perform_signv4_signature(request,
                                                        ctx->aws_region,
                                                        ctx->aws_service,
                                                        ctx->aws_provider);


        if (ret != 0) {
            flb_http_client_request_destroy(request, FLB_TRUE);

            return FLB_RETRY;
        }
    }

    response = flb_http_client_request_execute(request);

    if (response == NULL) {
        flb_debug("http request execution error");

        flb_http_client_request_destroy(request, FLB_TRUE);

        return FLB_RETRY;
    }
    /*
        * Only allow the following HTTP status:
        *
        * - 200: OK
        * - 201: Created
        * - 202: Accepted
        * - 203: no authorative resp
        * - 204: No Content
        * - 205: Reset content
        *
        */
    if ((response->status < 200 ||
         response->status > 205) &&
        response->status != 400) {
        if (ctx->log_response_payload &&
            response->body != NULL) {
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                            ctx->host, ctx->port,
                            response->status, response->body);
        }
        else {
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                            ctx->host, ctx->port, response->status);
        }
        out_ret = FLB_RETRY;
    }
    else if (response->status == 400) {
        /* Returned 400 status means unrecoverable. Immidiately
            * returning as a error. */
        if (ctx->log_response_payload &&
            response->body != NULL) {
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                            ctx->host, ctx->port,
                            response->status, response->body);
        }
        else {
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                            ctx->host, ctx->port, response->status);
        }
        out_ret = FLB_ERROR;
    }
    else {
        if (ctx->log_response_payload &&
            response->body != NULL) {
            flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                            ctx->host, ctx->port,
                            response->status, response->body);
        }
        else {
            flb_plg_debug(ctx->ins, "%s:%i, HTTP status=%i",
                            ctx->host, ctx->port,
                            response->status);
        }
    }

    flb_http_client_request_destroy(request, FLB_TRUE);

    return out_ret;
}

static int cb_prom_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    struct prometheus_remote_write_context *ctx;

    ctx = flb_prometheus_remote_write_context_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_output_set_context(ins, ctx);

    return 0;
}

static void append_labels(struct prometheus_remote_write_context *ctx,
                          struct cmt *cmt)
{
    struct flb_kv *kv;
    struct mk_list *head;

    mk_list_foreach(head, &ctx->kv_labels) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        cmt_label_add(cmt, kv->key, kv->val);
    }
}

static void cb_prom_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int c = 0;
    int ok;
    int ret;
    int result;
    cfl_sds_t encoded_chunk;
    flb_sds_t buf = NULL;
    size_t diff = 0;
    size_t off = 0;
    struct cmt *cmt;
    struct prometheus_remote_write_context *ctx = out_context;

    /* Initialize vars */
    ctx = out_context;
    ok = CMT_DECODE_MSGPACK_SUCCESS;
    result = FLB_OK;

    /* Buffer to concatenate multiple metrics contexts */
    buf = flb_sds_create_size(event_chunk->size);
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_plg_debug(ctx->ins, "cmetrics msgpack size: %lu",
                  event_chunk->size);

    /* Decode and encode every CMetric context */
    diff = 0;
    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) event_chunk->data,
                                            event_chunk->size, &off)) == ok) {
        /* append labels set by config */
        append_labels(ctx, cmt);

        /* Create a Prometheus Remote Write payload */
        encoded_chunk = cmt_encode_prometheus_remote_write_create(cmt);
        if (encoded_chunk == NULL) {
            flb_plg_error(ctx->ins,
                          "Error encoding context as prometheus remote write");
            result = FLB_ERROR;
            goto exit;
        }

        flb_plg_debug(ctx->ins, "cmetric_id=%i decoded %lu-%lu payload_size=%lu",
                      c, diff, off, flb_sds_len(encoded_chunk));
        c++;
        diff = off;

        /* concat buffer */
        flb_sds_cat_safe(&buf, encoded_chunk, flb_sds_len(encoded_chunk));

        /* release */
        cmt_encode_prometheus_remote_write_destroy(encoded_chunk);
        cmt_destroy(cmt);
    }

    if (ret == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA && c > 0) {
        flb_plg_debug(ctx->ins, "final payload size: %lu", flb_sds_len(buf));
        if (buf && flb_sds_len(buf) > 0) {
            /* Send HTTP request */
            result = http_post(ctx, buf, flb_sds_len(buf),
                               event_chunk->tag,
                               flb_sds_len(event_chunk->tag));

            /* Debug http_post() result statuses */
            if (result == FLB_OK) {
                flb_plg_debug(ctx->ins, "http_post result FLB_OK");
            }
            else if (result == FLB_ERROR) {
                flb_plg_debug(ctx->ins, "http_post result FLB_ERROR");
            }
            else if (result == FLB_RETRY) {
                flb_plg_debug(ctx->ins, "http_post result FLB_RETRY");
            }
        }
        flb_sds_destroy(buf);
        buf = NULL;
    }
    else {
        flb_plg_error(ctx->ins, "Error decoding msgpack encoded context");
    }

exit:
    if (buf) {
        flb_sds_destroy(buf);
    }
    FLB_OUTPUT_RETURN(result);
}

static int cb_prom_exit(void *data, struct flb_config *config)
{
    struct prometheus_remote_write_context *ctx;

    ctx = (struct prometheus_remote_write_context *) data;

    flb_prometheus_remote_write_context_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_1, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct prometheus_remote_write_context,
                                             add_labels),
     "Adds a custom label to the metrics use format: 'add_label name value'"
    },

    {
     FLB_CONFIG_MAP_STR, "proxy", NULL,
     0, FLB_FALSE, 0,
     "Specify an HTTP Proxy. The expected format of this value is http://host:port. "
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, http_user),
     "Set HTTP auth user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, http_passwd),
     "Set HTTP auth password"
    },
    {
     FLB_CONFIG_MAP_STR, "compression", "snappy",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, compression),
     "Compress the payload with either snappy, gzip if set"
    },

#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
    {
     FLB_CONFIG_MAP_BOOL, "aws_auth", "false",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, has_aws_auth),
     "Enable AWS SigV4 authentication"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_service", "aps",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, aws_service),
     "AWS destination service code, used by SigV4 authentication"
    },
    FLB_AWS_CREDENTIAL_BASE_CONFIG_MAP(FLB_PROMETHEUS_REMOTE_WRITE_CREDENTIAL_PREFIX),
#endif
#endif
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct prometheus_remote_write_context, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, uri),
     "Specify an optional HTTP URI for the target web server, e.g: /something"
    },
    {
     FLB_CONFIG_MAP_BOOL, "log_response_payload", "true",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, log_response_payload),
     "Specify if the response paylod should be logged or not"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_prometheus_remote_write_plugin = {
    .name        = "prometheus_remote_write",
    .description = "Prometheus remote write",
    .cb_init     = cb_prom_init,
    .cb_flush    = cb_prom_flush,
    .cb_exit     = cb_prom_exit,
    .config_map  = config_map,
    .event_type  = FLB_OUTPUT_METRICS,
    .workers     = 2,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
