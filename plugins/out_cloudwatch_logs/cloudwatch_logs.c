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

static int validate_log_group_class(struct flb_cloudwatch *ctx)
{
    if (ctx->create_group == FLB_FALSE) {
        return 0;
    }

    if (ctx->log_group_class == NULL || strlen(ctx->log_group_class) == 0) {
        ctx->log_group_class_type = LOG_CLASS_DEFAULT_TYPE;
        ctx->log_group_class = LOG_CLASS_STANDARD;
        return 0;
    } else if (strncmp(ctx->log_group_class, LOG_CLASS_STANDARD, LOG_CLASS_STANDARD_LEN) == 0) {
        flb_plg_debug(ctx->ins, "Using explicitly configured `log_group_class %s`, which is the default log class.", ctx->log_group_class);
        ctx->log_group_class_type = LOG_CLASS_STANDARD_TYPE;
        return 0;
    } else if (strncmp(ctx->log_group_class, LOG_CLASS_INFREQUENT_ACCESS, LOG_CLASS_INFREQUENT_ACCESS_LEN) == 0) {
        flb_plg_warn(ctx->ins, "Configured `log_group_class %s` will only apply to log groups created by Fluent Bit. "
                     "Look for the `Created log group` info level message emitted when a group does not already exist and is created.", ctx->log_group_class);
        ctx->log_group_class_type = LOG_CLASS_INFREQUENT_ACCESS_TYPE;
        return 0;
    }

    flb_plg_error(ctx->ins, "The valid values for log_group_class are {%s, %s}. Invalid input was %s", LOG_CLASS_STANDARD, LOG_CLASS_INFREQUENT_ACCESS, ctx->log_group_class);

    return -1;
}

static int cb_cloudwatch_init(struct flb_output_instance *ins,
                              struct flb_config *config, void *data)
{
    const char *tmp;
    char *session_name = NULL;
    struct flb_cloudwatch *ctx = NULL;
    int ret;
    flb_sds_t tmp_sds = NULL;
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
        ctx->group_name = flb_sds_create(tmp);
        if (!ctx->group_name) {
            flb_plg_error(ctx->ins, "Could not create log group context property");
            goto error;
        }
    } else {
        flb_plg_error(ctx->ins, "'log_group_name' is a required field");
        goto error;
    }

    tmp = flb_output_get_property("log_stream_name", ins);
    if (tmp) {
        ctx->log_stream_name = tmp;
        ctx->stream_name = flb_sds_create(tmp);
        if (!ctx->stream_name) {
            flb_plg_error(ctx->ins, "Could not create log group context property");
            goto error;
        }
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

    tmp = flb_output_get_property("log_group_template", ins);
    if (tmp) {
        ctx->ra_group = flb_ra_create((char *) tmp, FLB_FALSE);
        if (ctx->ra_group == NULL) {
            flb_plg_error(ctx->ins, "Could not parse `log_group_template`");
            goto error;
        }
    }

    tmp = flb_output_get_property("log_stream_template", ins);
    if (tmp) {
        ctx->ra_stream = flb_ra_create((char *) tmp, FLB_FALSE);
        if (ctx->ra_stream == NULL) {
            flb_plg_error(ctx->ins, "Could not parse `log_stream_template`");
            goto error;
        }
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

    tmp = flb_output_get_property("extra_user_agent", ins);
    if (tmp) {
        ctx->extra_user_agent = tmp;
    }

    tmp = flb_output_get_property("region", ins);
    if (tmp) {
        ctx->region = tmp;
    } else {
        flb_plg_error(ctx->ins, "'region' is a required field");
        goto error;
    }

    tmp = flb_output_get_property("metric_namespace", ins);
    if (tmp)
    {
        flb_plg_info(ctx->ins, "Metric Namespace=%s", tmp);
        ctx->metric_namespace = flb_sds_create(tmp);
    }

    tmp = flb_output_get_property("metric_dimensions", ins);
    if (tmp)
    {
        flb_plg_info(ctx->ins, "Metric Dimensions=%s", tmp);
        ctx->metric_dimensions = flb_utils_split(tmp, ';', 256);
    }

    ctx->create_group = FLB_FALSE;
    tmp = flb_output_get_property("auto_create_group", ins);
    if (tmp) {
        ctx->create_group = flb_utils_bool(tmp);
    }

    ctx->retry_requests = FLB_TRUE;
    tmp = flb_output_get_property("auto_retry_requests", ins);
    /* native plugins use On/Off as bool, the old Go plugin used true/false */
    if (tmp && (strcasecmp(tmp, "Off") == 0 || strcasecmp(tmp, "false") == 0)) {
        ctx->retry_requests = FLB_FALSE;
    }

    ctx->log_retention_days = 0;
    tmp = flb_output_get_property("log_retention_days", ins);
    if (tmp) {
        ctx->log_retention_days = atoi(tmp);
    }

    tmp = flb_output_get_property("role_arn", ins);
    if (tmp) {
        ctx->role_arn = tmp;
    }

    tmp = flb_output_get_property("sts_endpoint", ins);
    if (tmp) {
        ctx->sts_endpoint = (char *) tmp;
    }

    ret = validate_log_group_class(ctx);
    if (ret < 0) {
        goto error;
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
                                     ins->tls_verify,
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
                                                           (char *) ctx->sts_endpoint,
                                                           NULL,
                                                           flb_aws_client_generator(),
                                                           (char *) ctx->profile);
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
    ctx->aws_provider->provider_vtable->upstream_set(ctx->aws_provider, ctx->ins);

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
    ctx->cw_client->port = (ins->host.port != 0) ? ins->host.port : 443;
    ctx->cw_client->flags = (ins->use_tls) ? FLB_IO_TLS : FLB_IO_TCP;
    ctx->cw_client->proxy = NULL;
    ctx->cw_client->static_headers = &content_type_header;
    ctx->cw_client->static_headers_len = 1;
    tmp_sds = flb_sds_create(ctx->extra_user_agent);
    if (!tmp_sds) {
        flb_errno();
        goto error;
    }
    ctx->cw_client->extra_user_agent = tmp_sds;
    ctx->cw_client->retry_requests = ctx->retry_requests;

    struct flb_upstream *upstream = flb_upstream_create(config, ctx->endpoint,
                                                        ctx->cw_client->port,
                                                        ctx->cw_client->flags,
                                                        ctx->client_tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "Connection initialization error");
        goto error;
    }

    ctx->cw_client->upstream = upstream;
    flb_output_upstream_set(upstream, ctx->ins);
    ctx->cw_client->host = ctx->endpoint;

    struct mk_list *head;
    struct flb_filter_instance *f_ins;
    mk_list_foreach(head, &config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
        if (strstr(f_ins->p->name, "kubernetes")) {
            ctx->kubernete_metadata_enabled = true;
        }
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;

error:
    flb_free(session_name);
    flb_plg_error(ctx->ins, "Initialization failed");
    flb_cloudwatch_ctx_destroy(ctx);
    return -1;
}

struct cw_flush *new_buffer()
{
    struct cw_flush *buf;

    buf = flb_calloc(1, sizeof(struct cw_flush));
    if (!buf) {
        flb_errno();
        return NULL;
    }

    buf->out_buf = flb_malloc(PUT_LOG_EVENTS_PAYLOAD_SIZE);
    if (!buf->out_buf) {
        flb_errno();
        cw_flush_destroy(buf);
        return NULL;
    }
    buf->out_buf_size = PUT_LOG_EVENTS_PAYLOAD_SIZE;

    buf->tmp_buf = flb_malloc(sizeof(char) * PUT_LOG_EVENTS_PAYLOAD_SIZE);
    if (!buf->tmp_buf) {
        flb_errno();
        cw_flush_destroy(buf);
        return NULL;
    }
    buf->tmp_buf_size = PUT_LOG_EVENTS_PAYLOAD_SIZE;

    buf->events = flb_malloc(sizeof(struct cw_event) * MAX_EVENTS_PER_PUT);
    if (!buf->events) {
        flb_errno();
        cw_flush_destroy(buf);
        return NULL;
    }
    buf->events_capacity = MAX_EVENTS_PER_PUT;

    return buf;
}

static void cb_cloudwatch_flush(struct flb_event_chunk *event_chunk,
                                struct flb_output_flush *out_flush,
                                struct flb_input_instance *i_ins,
                                void *out_context,
                                struct flb_config *config)
{
    struct flb_cloudwatch *ctx = out_context;
    int event_count;
    (void) i_ins;
    (void) config;

    struct cw_flush *buf;

    buf = new_buffer();
    if (!buf) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    event_count = process_and_send(ctx, i_ins->p->name, buf, event_chunk->tag, event_chunk->data, event_chunk->size,
                                   event_chunk->type);
    if (event_count < 0) {
        flb_plg_error(ctx->ins, "Failed to send events");
        cw_flush_destroy(buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    cw_flush_destroy(buf);

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

        if (ctx->cw_client) {
            flb_aws_client_destroy(ctx->cw_client);
        }

        if (ctx->custom_endpoint == FLB_FALSE) {
            flb_free(ctx->endpoint);
        }

        if (ctx->ra_group) {
            flb_ra_destroy(ctx->ra_group);
        }

        if (ctx->ra_stream) {
            flb_ra_destroy(ctx->ra_stream);
        }

        if (ctx->group_name) {
            flb_sds_destroy(ctx->group_name);
        }

        if (ctx->stream_name) {
            flb_sds_destroy(ctx->stream_name);
        }

        if (ctx->metric_namespace) {
            flb_sds_destroy(ctx->metric_namespace);
        }

        mk_list_foreach_safe(head, tmp, &ctx->streams) {
            stream = mk_list_entry(head, struct log_stream, _head);
            mk_list_del(&stream->_head);
            log_stream_destroy(stream);
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

void entity_destroy(entity *entity) {
    if(entity->attributes) {
        flb_free(entity->attributes->cluster_name);
        flb_free(entity->attributes->instance_id);
        flb_free(entity->attributes->namespace);
        flb_free(entity->attributes->node);
        flb_free(entity->attributes->platform_type);
        flb_free(entity->attributes->workload);
        flb_free(entity->attributes->name_source);
        flb_free(entity->attributes);
    }
    if(entity->key_attributes) {
        flb_free(entity->key_attributes->environment);
        flb_free(entity->key_attributes->name);
        flb_free(entity->key_attributes->type);
        flb_free(entity->key_attributes->account_id);
        flb_free(entity->key_attributes);
    }
    flb_free(entity);
}

void log_stream_destroy(struct log_stream *stream)
{
    if (stream) {
        if (stream->name) {
            flb_sds_destroy(stream->name);
        }
        if (stream->group) {
            flb_sds_destroy(stream->group);
        }
        if (stream->entity) {
            entity_destroy(stream->entity);
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
     FLB_CONFIG_MAP_STR, "log_group_template", NULL,
     0, FLB_FALSE, 0,
     "Template for CW Log Group name using record accessor syntax. "
     "Plugin falls back to the log_group_name configured if needed."
    },

    {
     FLB_CONFIG_MAP_STR, "log_stream_template", NULL,
     0, FLB_FALSE, 0,
     "Template for CW Log Stream name using record accessor syntax. "
     "Plugin falls back to the log_stream_name or log_stream_prefix configured if needed."
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
     FLB_CONFIG_MAP_STR, "extra_user_agent", NULL,
     0, FLB_FALSE, 0,
     "This option appends a string to the default user agent. "
     "AWS asks that you not manually set this field yourself, "
     "it is reserved for use in our vended configurations, "
     "for example, EKS Container Insights."
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
     FLB_CONFIG_MAP_BOOL, "auto_retry_requests", "true",
     0, FLB_FALSE, 0,
     "Immediately retry failed requests to AWS services once. This option "
     "does not affect the normal Fluent Bit retry mechanism with backoff. "
     "Instead, it enables an immediate retry with no delay for networking "
     "errors, which may help improve throughput when there are transient/random "
     "networking issues."
    },

    {
     FLB_CONFIG_MAP_INT, "log_retention_days", "0",
     0, FLB_FALSE, 0,
     "If set to a number greater than zero, and newly create log group's "
     "retention policy is set to this many days. "
     "Valid values are: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653]"
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

    {
     FLB_CONFIG_MAP_STR, "external_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_cloudwatch, external_id),
    "Specify an external ID for the STS API, can be used with the role_arn parameter if your role "
     "requires an external ID."
    },

    {
     FLB_CONFIG_MAP_STR, "metric_namespace", NULL,
     0, FLB_FALSE, 0,
     "Metric namespace for CloudWatch EMF logs"
    },

    {
     FLB_CONFIG_MAP_STR, "metric_dimensions", NULL,
     0, FLB_FALSE, 0,
     "Metric dimensions is a list of lists. If you have only one list of "
     "dimensions, put the values as a comma seperated string. If you want to put "
     "list of lists, use the list as semicolon seperated strings. If your value "
     "is 'd1,d2;d3', we will consider it as [[d1, d2],[d3]]."
    },

    {
     FLB_CONFIG_MAP_STR, "profile", NULL,
     0, FLB_TRUE, offsetof(struct flb_cloudwatch, profile),
     "AWS Profile name. AWS Profiles can be configured with AWS CLI and are usually stored in "
     "$HOME/.aws/ directory."
    },

    {
     FLB_CONFIG_MAP_STR, "log_group_class", "",
     0, FLB_TRUE, offsetof(struct flb_cloudwatch, log_group_class),
     "Specify the log storage class. Valid values are STANDARD (default) and INFREQUENT_ACCESS."
    },

    {
    FLB_CONFIG_MAP_BOOL, "add_entity", "false",
    0, FLB_TRUE, offsetof(struct flb_cloudwatch, add_entity),
    "add entity to PutLogEvent calls"
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
    .workers      = 1,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,

    /* Configuration */
    .config_map     = config_map,
};
