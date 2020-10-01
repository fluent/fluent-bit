/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_utils.h>

#include <monkey/mk_core.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>

#include "cloudwatch_logs.h"
#include "cloudwatch_api.h"

static struct flb_aws_header content_type_header = {
    .key = "Content-Type",
    .key_len = 12,
    .val = "application/x-amz-json-1.1",
    .val_len = 26,
};

static int cb_cloudwatch_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    const char *tmp;
    char *session_name = NULL;
    struct flb_cloudwatch *ctx = NULL;
    struct cw_flush *buf = NULL;
    int ret;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_cloudwatch));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    mk_list_init(&ctx->streams);

    ctx->ins = ins;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        goto error;
    }

    tmp = flb_output_get_property("log_group_name", ins);
    if (tmp) {
        ctx->log_group = tmp;
    } else {
        flb_plg_error(ctx->ins, "'log_group_name' is a required field");
        goto error;
    }

    tmp = flb_output_get_property("log_stream_name", ins);
    if (tmp) {
        ctx->log_stream_name = tmp;
    }

    tmp = flb_output_get_property("log_stream_prefix", ins);
    if (tmp) {
        ctx->log_stream_prefix = tmp;
    }

    if (!ctx->log_stream_name && !ctx->log_stream_prefix) {
        flb_plg_error(ctx->ins, "Either 'log_stream_name' or 'log_stream_prefix'"
                      " is required");
        goto error;
    }

    if (ctx->log_stream_name && ctx->log_stream_prefix) {
        flb_plg_error(ctx->ins, "Either 'log_stream_name' or 'log_stream_prefix'"
                      " is required");
        goto error;
    }

    tmp = flb_output_get_property("log_format", ins);
    if (tmp) {
        ctx->log_format = tmp;
    }

    tmp = flb_output_get_property("endpoint", ins);
    if (tmp) {
        ctx->custom_endpoint = FLB_TRUE;
        ctx->endpoint = removeProtocol((char *) tmp, "https://");
    }
    else {
        ctx->custom_endpoint = FLB_FALSE;
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

    ctx->create_group = FLB_FALSE;
    tmp = flb_output_get_property("auto_create_group", ins);
    /* native plugins use On/Off as bool, the old Go plugin used true/false */
    if (tmp && (strcasecmp(tmp, "On") == 0 || strcasecmp(tmp, "true") == 0)) {
        ctx->create_group = FLB_TRUE;
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        ctx->role_arn = tmp;
    }

    tmp = flb_output_get_property("sts_endpoint", ins);
    if (tmp) {
        ctx->sts_endpoint = (char *) tmp;
    }

    ctx->group_created = FLB_FALSE;

    /* init log streams */
    if (ctx->log_stream_name) {
        ctx->stream.name = flb_sds_create(ctx->log_stream_name);
        if (!ctx->stream.name) {
            flb_errno();
            goto error;
        }
        ctx->stream_created = FLB_FALSE;
    }

    /* one tls instance for provider, one for cw client */
    ctx->cred_tls.context = flb_tls_context_new(FLB_TRUE,
                                                ins->tls_debug,
                                                ins->tls_vhost,
                                                ins->tls_ca_path,
                                                ins->tls_ca_file,
                                                ins->tls_crt_file,
                                                ins->tls_key_file,
                                                ins->tls_key_passwd);

    if (!ctx->cred_tls.context) {
        flb_plg_error(ctx->ins, "Failed to create tls context");
        goto error;
    }

    ctx->client_tls.context = flb_tls_context_new(FLB_TRUE,
                                                  ins->tls_debug,
                                                  ins->tls_vhost,
                                                  ins->tls_ca_path,
                                                  ins->tls_ca_file,
                                                  ins->tls_crt_file,
                                                  ins->tls_key_file,
                                                  ins->tls_key_passwd);
    if (!ctx->client_tls.context) {
        flb_plg_error(ctx->ins, "Failed to create tls context");
        goto error;
    }

    ctx->aws_provider = flb_standard_chain_provider_create(config,
                                                           &ctx->cred_tls,
                                                           (char *) ctx->region,
                                                           (char *) ctx->sts_endpoint,
                                                           NULL,
                                                           flb_aws_client_generator());
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
        ctx->sts_tls.context = flb_tls_context_new(FLB_TRUE,
                                                   ins->tls_debug,
                                                   ins->tls_vhost,
                                                   ins->tls_ca_path,
                                                   ins->tls_ca_file,
                                                   ins->tls_crt_file,
                                                   ins->tls_key_file,
                                                   ins->tls_key_passwd);
        if (!ctx->sts_tls.context) {
            flb_errno();
            goto error;
        }

        ctx->base_aws_provider = ctx->aws_provider;

        ctx->aws_provider = flb_sts_provider_create(config,
                                                    &ctx->sts_tls,
                                                    ctx->base_aws_provider,
                                                    NULL,
                                                    (char *) ctx->role_arn,
                                                    session_name,
                                                    (char *) ctx->region,
                                                    (char *) ctx->sts_endpoint,
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

    if (ctx->endpoint == NULL) {
        ctx->endpoint = flb_aws_endpoint("logs", (char *) ctx->region);
        if (!ctx->endpoint) {
            goto error;
        }
    }

    struct flb_aws_client_generator *generator = flb_aws_client_generator();
    ctx->cw_client = generator->create();
    if (!ctx->cw_client) {
        goto error;
    }
    ctx->cw_client->name = "cw_client";
    ctx->cw_client->has_auth = FLB_TRUE;
    ctx->cw_client->provider = ctx->aws_provider;
    ctx->cw_client->region = (char *) ctx->region;
    ctx->cw_client->service = "logs";
    ctx->cw_client->port = 443;
    ctx->cw_client->flags = 0;
    ctx->cw_client->proxy = NULL;
    ctx->cw_client->static_headers = &content_type_header;
    ctx->cw_client->static_headers_len = 1;

    struct flb_upstream *upstream = flb_upstream_create(config, ctx->endpoint,
                                                        443, FLB_IO_TLS,
                                                        &ctx->client_tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "Connection initialization error");
        goto error;
    }

    /*
     * Remove async flag from upstream
     * CW output runs in sync mode; because the CW API currently requires
     * PutLogEvents requests to a log stream to be made serially
     */
    upstream->flags &= ~(FLB_IO_ASYNC);

    ctx->cw_client->upstream = upstream;
    ctx->cw_client->host = ctx->endpoint;

    /* alloc the payload/processing buffer */
    buf = flb_calloc(1, sizeof(struct cw_flush));
    if (!buf) {
        flb_errno();
        goto error;
    }

    buf->out_buf = flb_malloc(PUT_LOG_EVENTS_PAYLOAD_SIZE);
    if (!buf->out_buf) {
        flb_errno();
        cw_flush_destroy(buf);
        goto error;
    }
    buf->out_buf_size = PUT_LOG_EVENTS_PAYLOAD_SIZE;

    buf->tmp_buf = flb_malloc(sizeof(char) * PUT_LOG_EVENTS_PAYLOAD_SIZE);
    if (!buf->tmp_buf) {
        flb_errno();
        cw_flush_destroy(buf);
        goto error;
    }
    buf->tmp_buf_size = PUT_LOG_EVENTS_PAYLOAD_SIZE;

    buf->events = flb_malloc(sizeof(struct cw_event) * MAX_EVENTS_PER_PUT);
    if (!buf->events) {
        flb_errno();
        cw_flush_destroy(buf);
        goto error;
    }
    buf->events_capacity = MAX_EVENTS_PER_PUT;

    ctx->buf = buf;


    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;

error:
    flb_free(session_name);
    flb_plg_error(ctx->ins, "Initialization failed");
    flb_cloudwatch_ctx_destroy(ctx);
    return -1;
}

static void cb_cloudwatch_flush(const void *data, size_t bytes,
                                const char *tag, int tag_len,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    struct flb_cloudwatch *ctx = out_context;
    int ret;
    int event_count;
    struct log_stream *stream = NULL;
    (void) i_ins;
    (void) config;

    ctx->buf->put_events_calls = 0;

    if (ctx->create_group == FLB_TRUE && ctx->group_created == FLB_FALSE) {
        ret = create_log_group(ctx);
        if (ret < 0) {
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    stream = get_log_stream(ctx, tag, tag_len);
    if (!stream) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    event_count = process_and_send(ctx, ctx->buf, stream, data, bytes);
    if (event_count < 0) {
        flb_plg_error(ctx->ins, "Failed to send events");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_plg_info(ctx->ins, "Sent %d events to CloudWatch", event_count);

    FLB_OUTPUT_RETURN(FLB_OK);
}

void flb_cloudwatch_ctx_destroy(struct flb_cloudwatch *ctx)
{
    struct log_stream *stream;
    struct mk_list *tmp;
    struct mk_list *head;

    if (ctx != NULL) {
        if (ctx->base_aws_provider) {
            flb_aws_provider_destroy(ctx->base_aws_provider);
        }

        if (ctx->buf) {
            cw_flush_destroy(ctx->buf);
        }

        if (ctx->aws_provider) {
            flb_aws_provider_destroy(ctx->aws_provider);
        }

        if (ctx->cred_tls.context) {
            flb_tls_context_destroy(ctx->cred_tls.context);
        }

        if (ctx->sts_tls.context) {
            flb_tls_context_destroy(ctx->sts_tls.context);
        }

        if (ctx->client_tls.context) {
            flb_tls_context_destroy(ctx->client_tls.context);
        }

        if (ctx->cw_client) {
            flb_aws_client_destroy(ctx->cw_client);
        }

        if (ctx->custom_endpoint == FLB_FALSE) {
            flb_free(ctx->endpoint);
        }

        if (ctx->log_stream_name) {
            if (ctx->stream.name) {
                flb_sds_destroy(ctx->stream.name);
            }
            if (ctx->stream.sequence_token) {
                flb_sds_destroy(ctx->stream.sequence_token);
            }
        } else {
            mk_list_foreach_safe(head, tmp, &ctx->streams) {
                stream = mk_list_entry(head, struct log_stream, _head);
                mk_list_del(&stream->_head);
                log_stream_destroy(stream);
            }
        }
        flb_free(ctx);
    }
}

static int cb_cloudwatch_exit(void *data, struct flb_config *config)
{
    struct flb_cloudwatch *ctx = data;

    flb_cloudwatch_ctx_destroy(ctx);
    return 0;
}

void log_stream_destroy(struct log_stream *stream)
{
    if (stream) {
        if (stream->name) {
            flb_sds_destroy(stream->name);
        }
        if (stream->sequence_token) {
            flb_sds_destroy(stream->sequence_token);
        }
        flb_free(stream);
    }
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "region", NULL,
     0, FLB_FALSE, 0,
     "The AWS region to send logs to"
    },

    {
     FLB_CONFIG_MAP_STR, "log_group_name", NULL,
     0, FLB_FALSE, 0,
     "CloudWatch Log Group Name"
    },

    {
     FLB_CONFIG_MAP_STR, "log_stream_name", NULL,
     0, FLB_FALSE, 0,
     "CloudWatch Log Stream Name; not compatible with `log_stream_prefix`"
    },

    {
     FLB_CONFIG_MAP_STR, "log_stream_prefix", NULL,
     0, FLB_FALSE, 0,
     "Prefix for CloudWatch Log Stream Name; the tag is appended to the prefix"
     " to form the stream name"
    },

    {
     FLB_CONFIG_MAP_STR, "log_key", NULL,
     0, FLB_FALSE, 0,
     "By default, the whole log record will be sent to CloudWatch. "
     "If you specify a key name with this option, then only the value of "
     "that key will be sent to CloudWatch. For example, if you are using "
     "the Fluentd Docker log driver, you can specify log_key log and only "
     "the log message will be sent to CloudWatch."
    },

    {
     FLB_CONFIG_MAP_STR, "log_format", NULL,
     0, FLB_FALSE, 0,
     "An optional parameter that can be used to tell CloudWatch the format "
     "of the data. A value of json/emf enables CloudWatch to extract custom "
     "metrics embedded in a JSON payload."
    },

    {
     FLB_CONFIG_MAP_STR, "role_arn", NULL,
     0, FLB_FALSE, 0,
     "ARN of an IAM role to assume (ex. for cross account access)."
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_create_group", "false",
     0, FLB_FALSE, 0,
     "Automatically create the log group (log streams will always automatically"
     " be created)"
    },

    {
     FLB_CONFIG_MAP_STR, "endpoint", NULL,
     0, FLB_FALSE, 0,
     "Specify a custom endpoint for the CloudWatch Logs API"
    },

    {
     FLB_CONFIG_MAP_STR, "sts_endpoint", NULL,
     0, FLB_FALSE, 0,
     "Specify a custom endpoint for the STS API, can be used with the role_arn parameter"
    },

    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_cloudwatch_logs_plugin = {
    .name         = "cloudwatch_logs",
    .description  = "Send logs to Amazon CloudWatch",
    .cb_init      = cb_cloudwatch_init,
    .cb_flush     = cb_cloudwatch_flush,
    .cb_exit      = cb_cloudwatch_exit,
    .flags        = 0,

    /* Configuration */
    .config_map     = config_map,
};
