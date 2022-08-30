/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
    flb_sockfd_t server_fd;            /* server socket */
    flb_pipefd_t coll_fd;              /* server handler */
    struct flb_input_instance *ins;    /* input instance */
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

static void pack_string(msgpack_packer *mp_pck, char *str, ssize_t len)
{
    if (len < 0) {
        len = strlen(str);
    }
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, str, len);
}

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

static int statsd_process_message(msgpack_packer *mp_pck,
                                  struct statsd_message *m)
{
    msgpack_pack_array(mp_pck, 2);
    flb_pack_time_now(mp_pck);

    switch (m->type) {
    case STATSD_TYPE_COUNTER:
        msgpack_pack_map(mp_pck, 4);
        pack_string(mp_pck, "type", 4);
        pack_string(mp_pck, "counter", 7);
        pack_string(mp_pck, "bucket", 6);
        pack_string(mp_pck, m->bucket, m->bucket_len);
        pack_string(mp_pck, "value", 5);
        msgpack_pack_double(mp_pck, atof(m->value));
        pack_string(mp_pck, "sample_rate", 11);
        msgpack_pack_double(mp_pck, m->sample_rate);
        break;
    case STATSD_TYPE_GAUGE:
        msgpack_pack_map(mp_pck, 4);
        pack_string(mp_pck, "type", 4);
        pack_string(mp_pck, "gauge", 5);
        pack_string(mp_pck, "bucket", 6);
        pack_string(mp_pck, m->bucket, m->bucket_len);
        pack_string(mp_pck, "value", 5);
        msgpack_pack_double(mp_pck, atof(m->value));
        pack_string(mp_pck, "incremental", 11);
        msgpack_pack_int(mp_pck, is_incremental(m->value));
        break;
    case STATSD_TYPE_TIMER:
        msgpack_pack_map(mp_pck, 4);
        pack_string(mp_pck, "type", 4);
        pack_string(mp_pck, "timer", 5);
        pack_string(mp_pck, "bucket", 6);
        pack_string(mp_pck, m->bucket, m->bucket_len);
        pack_string(mp_pck, "value", 5);
        msgpack_pack_double(mp_pck, atof(m->value));
        pack_string(mp_pck, "sample_rate", 11);
        msgpack_pack_double(mp_pck, m->sample_rate);
        break;
    case STATSD_TYPE_SET:
        msgpack_pack_map(mp_pck, 3);
        pack_string(mp_pck, "type", 4);
        pack_string(mp_pck, "set", 3);
        pack_string(mp_pck, "bucket", 6);
        pack_string(mp_pck, m->bucket, m->bucket_len);
        pack_string(mp_pck, "value", 5);
        pack_string(mp_pck, m->value, m->value_len);
        break;
    }
    return 0;
}

static int statsd_process_line(struct flb_statsd *ctx,
                               msgpack_packer *mp_pck, char *line)
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

    return statsd_process_message(mp_pck, &m);
}


static int cb_statsd_receive(struct flb_input_instance *ins,
                             struct flb_config *config, void *data)
{
    char *line;
    int len;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_statsd *ctx = data;

    /* Receive a UDP datagram */
    len = recv(ctx->server_fd, ctx->buf, MAX_PACKET_SIZE - 1, 0);
    if (len < 0) {
        flb_errno();
        return -1;
    }
    ctx->buf[len] = '\0';

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Process all messages in buffer */
    line = strtok(ctx->buf, "\n");
    while (line) {
        flb_plg_trace(ctx->ins, "received a line: '%s'", line);
        if (statsd_process_line(ctx, &mp_pck, line) < 0) {
            flb_plg_error(ctx->ins, "failed to process line: '%s'", line);
        }
        line = strtok(NULL, "\n");
    }

    /* Send to output */
    if (mp_sbuf.size > 0) {
        flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
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

    ctx->buf = flb_malloc(MAX_PACKET_SIZE);
    if (!ctx->buf) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
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
    ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);
    if (ctx->server_fd == -1) {
        flb_plg_error(ctx->ins, "can't bind to %s:%s", ctx->listen, ctx->port);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    /* Set up the UDP connection callback */
    ctx->coll_fd = flb_input_set_collector_socket(ins, cb_statsd_receive,
                                                  ctx->server_fd, config);
    if (ctx->coll_fd == -1) {
        flb_plg_error(ctx->ins, "cannot set up connection callback ");
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

    flb_socket_close(ctx->server_fd);
    flb_free(ctx->buf);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
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
    .flags        = 0
};
