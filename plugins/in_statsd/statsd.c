/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_pack.h>

#define MAX_PACKET_SIZE 65536
#define DEFAULT_LISTEN "0.0.0.0"
#define DEFAULT_PORT 8125

#define STATSD_TYPE_COUNTER 1
#define STATSD_TYPE_GAUGE   2
#define STATSD_TYPE_TIMER   3
#define STATSD_TYPE_SET     4

struct flb_statsd {
    char *buf;                         /* buffer */
    char listen[256];                  /* listening address (RFC-2181) */
    char port[6];                      /* listening port (RFC-793) */
    int  metrics;                      /* Import as metrics */
    flb_sockfd_t server_fd;            /* server socket */
    flb_pipefd_t coll_fd;              /* server handler */
    struct flb_input_instance *ins;    /* input instance */
    struct flb_log_event_encoder *log_encoder;
};

/*
 * The "statsd_message" represents a single line in UDP packet.
 * It's just a bunch of pointers to ephemeral buffer.
 */
struct statsd_message {
    char *bucket;
    int bucket_len;
    char *value;
    int value_len;
    int type;
    double sample_rate;
};

static int get_statsd_type(char *str)
{
    switch (*str) {
    case 'g':
        return STATSD_TYPE_GAUGE;
    case 's':
        return STATSD_TYPE_SET;
    case 'c':
        return STATSD_TYPE_COUNTER;
    case 'm':
        if (*(str + 1) == 's') {
            return STATSD_TYPE_TIMER;
        }
    }
    return STATSD_TYPE_COUNTER;
}

static int is_incremental(char *str)
{
    return (*str == '+' || *str == '-');
}

static int statsd_process_message(struct flb_statsd *ctx,
                                  struct statsd_message *m)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        switch (m->type) {
        case STATSD_TYPE_COUNTER:
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,

                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_CSTRING_VALUE("counter"),
                    FLB_LOG_EVENT_CSTRING_VALUE("bucket"),
                    FLB_LOG_EVENT_STRING_VALUE(m->bucket, m->bucket_len),
                    FLB_LOG_EVENT_CSTRING_VALUE("value"),
                    FLB_LOG_EVENT_DOUBLE_VALUE(strtod(m->value, NULL)),
                    FLB_LOG_EVENT_CSTRING_VALUE("sample_rate"),
                    FLB_LOG_EVENT_DOUBLE_VALUE(m->sample_rate));

            break;
        case STATSD_TYPE_GAUGE:
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,

                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_CSTRING_VALUE("gauge"),
                    FLB_LOG_EVENT_CSTRING_VALUE("bucket"),
                    FLB_LOG_EVENT_STRING_VALUE(m->bucket, m->bucket_len),
                    FLB_LOG_EVENT_CSTRING_VALUE("value"),
                    FLB_LOG_EVENT_DOUBLE_VALUE(strtod(m->value, NULL)),
                    FLB_LOG_EVENT_CSTRING_VALUE("incremental"),
                    FLB_LOG_EVENT_INT64_VALUE(is_incremental(m->value)));
            break;
        case STATSD_TYPE_TIMER:
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,

                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_CSTRING_VALUE("timer"),
                    FLB_LOG_EVENT_CSTRING_VALUE("bucket"),
                    FLB_LOG_EVENT_STRING_VALUE(m->bucket, m->bucket_len),
                    FLB_LOG_EVENT_CSTRING_VALUE("value"),
                    FLB_LOG_EVENT_DOUBLE_VALUE(strtod(m->value, NULL)),
                    FLB_LOG_EVENT_CSTRING_VALUE("sample_rate"),
                    FLB_LOG_EVENT_DOUBLE_VALUE(m->sample_rate));

        case STATSD_TYPE_SET:
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,

                    FLB_LOG_EVENT_CSTRING_VALUE("type"),
                    FLB_LOG_EVENT_CSTRING_VALUE("set"),
                    FLB_LOG_EVENT_CSTRING_VALUE("bucket"),
                    FLB_LOG_EVENT_STRING_VALUE(m->bucket, m->bucket_len),
                    FLB_LOG_EVENT_CSTRING_VALUE("value"),
                    FLB_LOG_EVENT_STRING_VALUE(m->value, m->value_len));
            break;
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    return ret;
}

static int statsd_process_line(struct flb_statsd *ctx, char *line)
{
    char *colon, *bar, *atmark;
    struct statsd_message m;

    /*
     * bucket:value|type|@sample_rate
     * ------
     */
    colon = strchr(line, ':');
    if (colon == NULL) {
        flb_plg_error(ctx->ins, "no bucket name found");
        return -1;
    }
    m.bucket = line;
    m.bucket_len = (colon - line);

    /*
     * bucket:value|type|@sample_rate
     *              ----
     */
    bar = strchr(colon + 1, '|');
    if (bar == NULL) {
        flb_plg_error(ctx->ins, "no metric type found");
        return -1;
    }
    m.type = get_statsd_type(bar + 1);

    /*
     * bucket:value|type|@sample_rate
     *        -----
     */
    m.value = colon + 1;
    m.value_len = (bar - colon - 1);

    /*
     * bucket:value|type|@sample_rate
     *                   ------------
     */
    atmark = strstr(bar + 1, "|@");
    if (atmark == NULL || atof(atmark + 2) == 0) {
        m.sample_rate = 1.0;
    }
    else {
        m.sample_rate = atof(atmark + 2);
    }

    return statsd_process_message(ctx, &m);
}


static int cb_statsd_receive(struct flb_input_instance *ins,
                             struct flb_config *config, void *data)
{
    int ret;
    int len;
    struct flb_statsd *ctx = data;
    struct cfl_list *head = NULL;
    struct cfl_list *kvs = NULL;
    struct cfl_split_entry *cur = NULL;
#ifdef FLB_HAVE_METRICS
    struct cmt *cmt = NULL;
    int cmt_flags = 0;
#endif

    /* Receive a UDP datagram */
    len = recv(ctx->server_fd, ctx->buf, MAX_PACKET_SIZE - 1, 0);
    if (len < 0) {
        flb_errno();
        return -1;
    }
    ctx->buf[len] = '\0';

#ifdef FLB_HAVE_METRICS
    if (ctx->metrics == FLB_TRUE) {
        cmt_flags |= CMT_DECODE_STATSD_GAUGE_OBSERVER;
        flb_plg_trace(ctx->ins, "received a buf: '%s'", ctx->buf);
        ret = cmt_decode_statsd_create(&cmt, ctx->buf, len, cmt_flags);
        if (ret != CMT_DECODE_STATSD_SUCCESS) {
            flb_plg_error(ctx->ins, "failed to process buf: '%s'", ctx->buf);
            return -1;
        }

        /* Append the updated metrics */
        ret = flb_input_metrics_append(ins, NULL, 0, cmt);
        if (ret != 0) {
            flb_plg_error(ins, "could not append metrics");
        }

        cmt_destroy(cmt);
    }
    else {
#endif
        ret = FLB_EVENT_ENCODER_SUCCESS;
        kvs = cfl_utils_split(ctx->buf, '\n', -1 );
        if (kvs == NULL) {
            goto split_error;
        }

        cfl_list_foreach(head, kvs) {
            cur = cfl_list_entry(head, struct cfl_split_entry, _head);
            flb_plg_trace(ctx->ins, "received a line: '%s'", cur->value);

            ret = statsd_process_line(ctx, cur->value);

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(ctx->ins, "failed to process line: '%s'", cur->value);

                break;
            }
        }

        if (kvs != NULL) {
            cfl_utils_split_free(kvs);
        }

        if (ctx->log_encoder->output_length > 0) {
            flb_input_log_append(ctx->ins, NULL, 0,
                                 ctx->log_encoder->output_buffer,
                                 ctx->log_encoder->output_length);
        }
        else {
            flb_plg_error(ctx->ins, "log event encoding error : %d", ret);
        }

        flb_log_event_encoder_reset(ctx->log_encoder);
#ifdef FLB_HAVE_METRICS
    }
#endif

    return 0;

split_error:
    return -1;
}

static int cb_statsd_init(struct flb_input_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_statsd *ctx;
    char *listen;
    int port;
    int ret;

    ctx = flb_calloc(1, sizeof(struct flb_statsd));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(ins, "could not initialize event encoder");
        flb_free(ctx);

        return -1;
    }

    ctx->buf = flb_malloc(MAX_PACKET_SIZE);
    if (!ctx->buf) {
        flb_errno();
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx);
        return -1;
    }

    /* Listening address */
    if (ins->host.listen) {
        listen = ins->host.listen;
    }
    else {
        listen = DEFAULT_LISTEN;
    }
    strncpy(ctx->listen, listen, sizeof(ctx->listen) - 1);

    /* Listening port */
    if (ins->host.port) {
        port = ins->host.port;
    }
    else {
        port = DEFAULT_PORT;
    }
    snprintf(ctx->port, sizeof(ctx->port), "%hu", (unsigned short) port);

    /* Export plugin context */
    flb_input_set_context(ins, ctx);

    /* Accepts metrics from UDP connections. */
    ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen, ins->net_setup.share_port);
    if (ctx->server_fd == -1) {
        flb_plg_error(ctx->ins, "can't bind to %s:%s", ctx->listen, ctx->port);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    /* Set up the UDP connection callback */
    ctx->coll_fd = flb_input_set_collector_socket(ins, cb_statsd_receive,
                                                  ctx->server_fd, config);
    if (ctx->coll_fd == -1) {
        flb_plg_error(ctx->ins, "cannot set up connection callback ");
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_socket_close(ctx->server_fd);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "start UDP server on %s:%s", ctx->listen, ctx->port);
    return 0;
}

static void cb_statsd_pause(void *data, struct flb_config *config)
{
    struct flb_statsd *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_statsd_resume(void *data, struct flb_config *config)
{
    struct flb_statsd *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int cb_statsd_exit(void *data, struct flb_config *config)
{
    struct flb_statsd *ctx = data;

    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    flb_socket_close(ctx->server_fd);
    flb_free(ctx->buf);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_BOOL, "metrics", "off",
    0, FLB_TRUE, offsetof(struct flb_statsd, metrics),
    "Ingest as metrics type of events."
   },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_statsd_plugin = {
    .name         = "statsd",
    .description  = "StatsD input plugin",
    .cb_init      = cb_statsd_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_statsd_pause,
    .cb_resume    = cb_statsd_resume,
    .cb_exit      = cb_statsd_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER,
};
