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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_output_plugin.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>

#include <fluent-bit/aws/flb_aws_compress.h>

#include <monkey/mk_core.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>

#include "firehose.h"
#include "firehose_api.h"

static struct flb_aws_header content_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "application/x-amz-json-1.1",
    .val_len = 26,
};

static int cb_firehose_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    const char *tmp;
    char *session_name = NULL;
    struct flb_firehose *ctx = NULL;
    int ret;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_firehose));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        goto error;
    }

    tmp = flb_output_get_property("delivery_stream", ins);
    if (tmp) {
        ctx->delivery_stream = tmp;
    } else {
        flb_plg_error(ctx->ins, "'delivery_stream' is a required field");
        goto error;
    }

    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        ctx->time_key = tmp;
    }

    tmp = flb_output_get_property("time_key_format", ins);
    if (tmp) {
        ctx->time_key_format = tmp;
    } else {
        ctx->time_key_format = DEFAULT_TIME_KEY_FORMAT;
    }

    tmp = flb_output_get_property("log_key", ins);
    if (tmp) {
        ctx->log_key = tmp;
    }

    if (ctx->log_key && ctx->time_key) {
        flb_plg_error(ctx->ins, "'time_key' and 'log_key' can not be used together");
        goto error;
    }

    tmp = flb_output_get_property("endpoint", ins);
    if (tmp) {
        ctx->custom_endpoint = FLB_TRUE;
        ctx->endpoint = removeProtocol((char *) tmp, "https://");
    }
    else {
        ctx->custom_endpoint = FLB_FALSE;
    }

    tmp = flb_output_get_property("sts_endpoint", ins);
    if (tmp) {
        ctx->sts_endpoint = (char *) tmp;
    }

    /*
     * Sets the port number for the Kinesis output plugin.
     *
     * This function uses the port number already set in the output instance's host structure.
     * If the port is not set (0), the default HTTPS port is used.
     *
     * @param ins The output instance.
     * @param ctx The Kinesis output plugin context.
     */
    flb_plg_debug(ins, "Retrieved port from ins->host.port: %d", ins->host.port);

    if (ins->host.port == 0) {
        ctx->port = FLB_KINESIS_DEFAULT_HTTPS_PORT;
        flb_plg_debug(ins, "Port not set. Using default HTTPS port: %d", ctx->port);
    }
    else if (ins->host.port == (ctx->port = (uint16_t)ins->host.port)) {
        flb_plg_debug(ins, "Setting port to: %d", ctx->port);
    }
    else {
        flb_plg_error(ins, "Invalid port number: %d. Must be between %d and %d",
                      ins->host.port, 1, UINT16_MAX);
        goto error;
    }

    tmp = flb_output_get_property("compression", ins);
    if (tmp) {
        ret = flb_aws_compression_get_type(tmp);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "unknown compression: %s", tmp);
            goto error;
        }
        ctx->compression = ret;
    }

    tmp = flb_output_get_property("log_key", ins);
    if (tmp) {
        ctx->log_key = tmp;
    }

    tmp = flb_output_get_property("region", ins);
    if (tmp) {
        ctx->region = tmp;
    } else {
        flb_plg_error(ctx->ins, "'region' is a required field");
        goto error;
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        ctx->role_arn = tmp;
    }

    /* one tls instance for provider, one for cw client */
    ctx->cred_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                   FLB_TRUE,
                                   ins->tls_debug,
                                   ins->tls_vhost,
                                   ins->tls_ca_path,
                                   ins->tls_ca_file,
                                   ins->tls_crt_file,
                                   ins->tls_key_file,
                                   ins->tls_key_passwd);

    if (!ctx->cred_tls) {
        flb_plg_error(ctx->ins, "Failed to create tls context");
        goto error;
    }

    ctx->client_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                     FLB_TRUE,
                                     ins->tls_debug,
                                     ins->tls_vhost,
                                     ins->tls_ca_path,
                                     ins->tls_ca_file,
                                     ins->tls_crt_file,
                                     ins->tls_key_file,
                                     ins->tls_key_passwd);
    if (!ctx->client_tls) {
        flb_plg_error(ctx->ins, "Failed to create tls context");
        goto error;
    }

    ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                           ctx->cred_tls,
                                                           (char *) ctx->region,
                                                           ctx->sts_endpoint,
                                                           NULL,
                                                           flb_aws_client_generator(),
                                                           ctx->profile);
    if (!ctx->aws_provider) {
        flb_plg_error(ctx->ins, "Failed to create AWS Credential Provider");
        goto error;
    }

    if(ctx->role_arn) {
        /* set up sts assume role provider */
        session_name = flb_sts_session_name();
        if (!session_name) {
            flb_plg_error(ctx->ins,
                          "Failed to generate random STS session name");
            goto error;
        }

        /* STS provider needs yet another separate TLS instance */
        ctx->sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                      FLB_TRUE,
                                      ins->tls_debug,
                                      ins->tls_vhost,
                                      ins->tls_ca_path,
                                      ins->tls_ca_file,
                                      ins->tls_crt_file,
                                      ins->tls_key_file,
                                      ins->tls_key_passwd);
        if (!ctx->sts_tls) {
            flb_errno();
            goto error;
        }

        ctx->base_aws_provider = ctx->aws_provider;

        ctx->aws_provider = flb_sts_provider_create(config,
                                                    ctx->sts_tls,
                                                    ctx->base_aws_provider,
                                                    (char *) ctx->external_id,
                                                    (char *) ctx->role_arn,
                                                    session_name,
                                                    (char *) ctx->region,
                                                    ctx->sts_endpoint,
                                                    NULL,
                                                    flb_aws_client_generator());
        if (!ctx->aws_provider) {
            flb_plg_error(ctx->ins,
                          "Failed to create AWS STS Credential Provider");
            goto error;
        }
        /* session name can freed after provider is created */
        flb_free(session_name);
        session_name = NULL;
    }

    /* initialize credentials and set to sync mode */
    ctx->aws_provider->provider_vtable->sync(ctx->aws_provider);
    ctx->aws_provider->provider_vtable->init(ctx->aws_provider);
    ctx->aws_provider->provider_vtable->upstream_set(ctx->aws_provider, ctx->ins);

    if (ctx->endpoint == NULL) {
        ctx->endpoint = flb_aws_endpoint("firehose", (char *) ctx->region);
        if (!ctx->endpoint) {
            goto error;
        }
    }

    struct flb_aws_client_generator *generator = flb_aws_client_generator();
    ctx->firehose_client = generator->create();
    if (!ctx->firehose_client) {
        goto error;
    }
    ctx->firehose_client->name = "firehose_client";
    ctx->firehose_client->has_auth = FLB_TRUE;
    ctx->firehose_client->provider = ctx->aws_provider;
    ctx->firehose_client->region = (char *) ctx->region;
    ctx->firehose_client->retry_requests = ctx->retry_requests;
    ctx->firehose_client->service = "firehose";
    ctx->firehose_client->port = ctx->port;
    ctx->firehose_client->flags = 0;
    ctx->firehose_client->proxy = NULL;
    ctx->firehose_client->static_headers = &content_type_header;
    ctx->firehose_client->static_headers_len = 1;

    struct flb_upstream *upstream = flb_upstream_create(config, ctx->endpoint,
                                                        ctx->port, FLB_IO_TLS,
                                                        ctx->client_tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "Connection initialization error");
        goto error;
    }

    ctx->firehose_client->upstream = upstream;
    flb_output_upstream_set(upstream, ctx->ins);

    ctx->firehose_client->host = ctx->endpoint;

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;

error:
    flb_free(session_name);
    flb_plg_error(ctx->ins, "Initialization failed");
    flb_firehose_ctx_destroy(ctx);
    return -1;
}

struct flush *new_flush_buffer()
{
    struct flush *buf;


    buf = flb_calloc(1, sizeof(struct flush));
    if (!buf) {
        flb_errno();
        return NULL;
    }

    buf->tmp_buf = flb_malloc(sizeof(char) * PUT_RECORD_BATCH_PAYLOAD_SIZE);
    if (!buf->tmp_buf) {
        flb_errno();
        flush_destroy(buf);
        return NULL;
    }
    buf->tmp_buf_size = PUT_RECORD_BATCH_PAYLOAD_SIZE;

    buf->events = flb_malloc(sizeof(struct firehose_event) * MAX_EVENTS_PER_PUT);
    if (!buf->events) {
        flb_errno();
        flush_destroy(buf);
        return NULL;
    }
    buf->events_capacity = MAX_EVENTS_PER_PUT;

    return buf;
}

static void cb_firehose_flush(struct flb_event_chunk *event_chunk,
                              struct flb_output_flush *out_flush,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    struct flb_firehose *ctx = out_context;
    int ret;
    struct flush *buf;
    (void) i_ins;
    (void) config;

    buf = new_flush_buffer();
    if (!buf) {
        flb_plg_error(ctx->ins, "Failed to construct flush buffer");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = process_and_send_records(ctx, buf,
                                   event_chunk->data, event_chunk->size, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to send records");
        flush_destroy(buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_plg_debug(ctx->ins, "Processed %d records, sent %d to %s",
                 buf->records_processed, buf->records_sent, ctx->delivery_stream);
    flush_destroy(buf);

    FLB_OUTPUT_RETURN(FLB_OK);
}

void flb_firehose_ctx_destroy(struct flb_firehose *ctx)
{
    if (ctx != NULL) {
        if (ctx->base_aws_provider) {
            flb_aws_provider_destroy(ctx->base_aws_provider);
        }

        if (ctx->aws_provider) {
            flb_aws_provider_destroy(ctx->aws_provider);
        }

        if (ctx->cred_tls) {
            flb_tls_destroy(ctx->cred_tls);
        }

        if (ctx->sts_tls) {
            flb_tls_destroy(ctx->sts_tls);
        }

        if (ctx->client_tls) {
            flb_tls_destroy(ctx->client_tls);
        }

        if (ctx->firehose_client) {
            flb_aws_client_destroy(ctx->firehose_client);
        }

        if (ctx->custom_endpoint == FLB_FALSE) {
            flb_free(ctx->endpoint);
        }

        flb_free(ctx);
    }
}

static int cb_firehose_exit(void *data, struct flb_config *config)
{
    struct flb_firehose *ctx = data;

    flb_firehose_ctx_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "region", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, region),
     "The AWS region of your delivery stream"
    },

    {
     FLB_CONFIG_MAP_STR, "delivery_stream", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, delivery_stream),
     "Firehose delivery stream name"
    },

    {
     FLB_CONFIG_MAP_STR, "time_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, time_key),
     "Add the timestamp to the record under this key. By default the timestamp "
     "from Fluent Bit will not be added to records sent to Kinesis."
    },

    {
     FLB_CONFIG_MAP_STR, "time_key_format", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, time_key_format),
     "strftime compliant format string for the timestamp; for example, "
     "the default is '%Y-%m-%dT%H:%M:%S'. This option is used with time_key. "
    },

    {
     FLB_CONFIG_MAP_STR, "role_arn", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, role_arn),
     "ARN of an IAM role to assume (ex. for cross account access)."
    },

    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_FALSE, 0,
     "Specify a custom endpoint for the Firehose API"
    },

    {
     FLB_CONFIG_MAP_STR, "sts_endpoint", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, sts_endpoint),
    "Custom endpoint for the STS API."
    },

    {
     FLB_CONFIG_MAP_STR, "external_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, external_id),
    "Specify an external ID for the STS API, can be used with the role_arn parameter if your role "
     "requires an external ID."
    },

    {
     FLB_CONFIG_MAP_STR, "compression", NULL,
     0, FLB_FALSE, 0,
    "Compression type for Firehose records. Each log record is individually compressed "
    "and sent to Firehose. 'gzip' and 'arrow' are the supported values. "
    "'arrow' is only an available if Apache Arrow was enabled at compile time. "
    "Defaults to no compression."
    },

    {
     FLB_CONFIG_MAP_STR, "log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, log_key),
     "By default, the whole log record will be sent to Firehose. "
     "If you specify a key name with this option, then only the value of "
     "that key will be sent to Firehose. For example, if you are using "
     "the Fluentd Docker log driver, you can specify `log_key log` and only "
     "the log message will be sent to Firehose."
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_retry_requests", "true",
     0, FLB_TRUE, offsetof(struct flb_firehose, retry_requests),
     "Immediately retry failed requests to AWS services once. This option "
     "does not affect the normal Fluent Bit retry mechanism with backoff. "
     "Instead, it enables an immediate retry with no delay for networking "
     "errors, which may help improve throughput when there are transient/random "
     "networking issues."
    },

    {
     FLB_CONFIG_MAP_STR, "profile", NULL,
     0, FLB_TRUE, offsetof(struct flb_firehose, profile),
     "AWS Profile name. AWS Profiles can be configured with AWS CLI and are usually stored in "
     "$HOME/.aws/ directory."
    },
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_kinesis_firehose_plugin = {
    .name         = "kinesis_firehose",
    .description  = "Send logs to Amazon Kinesis Firehose",
    .cb_init      = cb_firehose_init,
    .cb_flush     = cb_firehose_flush,
    .cb_exit      = cb_firehose_exit,
    .workers      = 1,
    .flags        = 0,

    /* Configuration */
    .config_map     = config_map,
};
