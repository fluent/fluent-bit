/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_pack.h>

#include <math.h>

#define MAX_PACKET_SIZE 65536
#define DEFAULT_LISTEN "0.0.0.0"
#define DEFAULT_PORT 8125
#define DEFAULT_INTERVAL_SEC 1
#define DEFAULT_INTERVAL_NSEC 0

#define STATSD_TYPE_COUNTER 1
#define STATSD_TYPE_GAUGE   2
#define STATSD_TYPE_TIMER   3
#define STATSD_TYPE_SET     4

#define alloc_nr(n) (n + 8) * 3 / 2;
#define square(x) ((x) * (x))

struct flb_statsd {
    char *buf;                         /* buffer */
    char listen[256];                  /* listening address (RFC-2181) */
    char port[6];                      /* listening port (RFC-793) */
    int interval_sec;                  /* emit interval */
    int interval_nsec;                 /* emit interval (sub-seconds) */
    flb_sockfd_t server_fd;            /* server socket */
    flb_pipefd_t coll_fd;              /* server handler */
    flb_pipefd_t timer_fd;             /* timer handler */
    struct flb_input_instance *i_ins;  /* input instance */
    struct mk_list buckets;            /* list of statsd_bucket */
};

/*
 * We store metrics received from UDP connections into this
 * bucket.
 */
struct statsd_bucket {
    flb_sds_t name;        /* bucket name */
    int type;              /* metric type */
    double counter;        /* counter */
    double gauge;          /* gauge */
    double *timer;         /* timer */
    int timer_nr;
    int timer_alloc;
    flb_sds_t *set;        /* set */
    int set_nr;
    int set_alloc;
    struct mk_list _head;
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

/*
 * Data structure for summarizing timer buckets. Field names
 * follow statsd's convention.
 */
struct statsd_agg {
    int count;
    double lower;
    double upper;
    double median;
    double mean;
    double sum;
    double sum_squares;
    double std;
};

static void pack_string(msgpack_packer *ppck, char *str)
{
    int len = strlen(str);
    msgpack_pack_str(ppck, len);
    msgpack_pack_str_body(ppck, str, len);
}

static int compare_double(const void *d1, const void *d2)
{
    return *((double *) d1) - *((double *) d2);
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
        if (memcmp(str, "ms", 2) == 0) {
            return STATSD_TYPE_TIMER;
        }
    }
    return STATSD_TYPE_COUNTER;
}

/*
 * A handful of helper functions to manipuate a bucket
 */
static int bucket_add_timer(struct statsd_bucket *b, double timer)
{
    double *ptr;
    int alloc;

    /* Ensure the array is large enough */
    if (b->timer_nr == b->timer_alloc) {
        alloc = alloc_nr(b->timer_alloc);
        ptr = flb_realloc(b->timer, sizeof(double) * alloc);
        if (ptr == NULL) {
            flb_errno();
            return -1;
        }
        b->timer = ptr;
        b->timer_alloc = alloc;
    }

    b->timer[b->timer_nr] = timer;
    b->timer_nr++;
    return 0;
}

static void bucket_describe_timer(struct statsd_bucket *b,
                                  struct statsd_agg *agg)
{
    int i;
    int nr = b->timer_nr;

    memset(agg, 0, sizeof(struct statsd_agg));
    if (nr == 0) {
        return;
    }
    agg->count = nr;

    /* min, max and median */
    qsort(b->timer, nr, sizeof(double), compare_double);
    agg->lower = b->timer[0];
    agg->upper = b->timer[nr - 1];

    if (nr % 2) {
        agg->median = b->timer[nr / 2];
    } else {
        agg->median = (b->timer[nr / 2] + b->timer[nr / 2 + 1]) / 2;
    }

    /* mean and stdev */
    for (i = 0; i < nr; i++) {
        agg->sum += b->timer[i];
        agg->sum_squares += square(b->timer[i]);
    }
    agg->mean = agg->sum / nr;
    agg->std = sqrt(agg->sum_squares / nr - square(agg->mean));
}

static void bucket_clear_timer(struct statsd_bucket *b)
{
    flb_free(b->timer);
    b->timer = NULL;
    b->timer_nr = 0;
    b->timer_alloc = 0;
}

static int bucket_add_item_to_set(struct statsd_bucket *b, char *str, int len)
{
    int i;
    int alloc;
    flb_sds_t *ptr, val;

    /* Existing already? just skip */
    for (i = 0; i < b->set_nr; i++) {
        if (flb_sds_cmp(b->set[i] , str, len) == 0) {
            return 0;
        }
    }

    /* Ensure the array is large enough */
    if (b->set_nr == b->set_alloc) {
        alloc = alloc_nr(b->set_alloc);
        ptr = flb_realloc(b->set, sizeof(flb_sds_t) * alloc);
        if (ptr == NULL) {
            flb_errno();
            return -1;
        }
        b->set = ptr;
        b->set_alloc = alloc;
    }

    val = flb_sds_create_len(str, len);
    if (val == NULL) {
        flb_errno();
        return -1;
    }

    b->set[b->set_nr] = val;
    b->set_nr++;
    return 0;
}

static void bucket_clear_set(struct statsd_bucket *b)
{
    int i;
    for (i = 0; i < b->set_nr; i++) {
        flb_sds_destroy(b->set[i]);
    }
    flb_free(b->set);
    b->set = NULL;
    b->set_nr = 0;
    b->set_alloc = 0;
}

/*
 * Main handlers
 */
static int statsd_add_bucket(struct flb_statsd *ctx, struct statsd_message *m,
                             struct statsd_bucket **new)
{
    struct statsd_bucket *b;

    b = flb_calloc(1, sizeof(struct statsd_bucket));
    if (b == NULL) {
        flb_errno();
        return -1;
    }

    b->name = flb_sds_create_len(m->bucket, m->bucket_len);
    if (b->name == NULL) {
        flb_free(b);
        return -1;
    }

    b->type = m->type;

    mk_list_add(&b->_head, &ctx->buckets);
    *new = b;
    return 0;
}

static int statsd_find_bucket(struct flb_statsd *ctx, struct statsd_message *m,
                              struct statsd_bucket **found)
{
    struct statsd_bucket *b;
    struct mk_list *head;
    char *name = m->bucket;
    int len = m->bucket_len;

    mk_list_foreach(head, &ctx->buckets) {
        b = mk_list_entry(head, struct statsd_bucket, _head);
        if (b->type == m->type && flb_sds_cmp(b->name, name, len) == 0) {
            *found = b;
            return 1;
        }
    }
    return 0;
}

static int statsd_process_message(struct flb_statsd *ctx,
                                  struct statsd_message *m)
{
    struct statsd_bucket *b;

    if (statsd_find_bucket(ctx, m, &b) == 0) {
        if (statsd_add_bucket(ctx, m, &b)) {
            return -1;
        }
    }

    switch (m->type) {
    case STATSD_TYPE_COUNTER:
        b->counter += atof(m->value) / m->sample_rate;
        break;
    case STATSD_TYPE_GAUGE:
        if (*m->value == '+' || *m->value == '-') {
            b->gauge += atof(m->value);
        }
        else {
            b->gauge = atof(m->value);
        }
        break;
    case STATSD_TYPE_TIMER:
        return bucket_add_timer(b, atof(m->value) / m->sample_rate);
    case STATSD_TYPE_SET:
        return bucket_add_item_to_set(b, m->value, m->value_len);
    }
    return 0;
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
        flb_error("[in_statsd] no bucket name found");
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
        flb_error("[in_statsd] no metric type found");
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


static int cb_statsd_receive(struct flb_input_instance *i_ins,
                             struct flb_config *config, void *data)
{
    struct flb_statsd *ctx = data;
    char *line;
    int len;

    /* Receive a UDP datagram */
    len = recv(ctx->server_fd, ctx->buf, MAX_PACKET_SIZE - 1, 0);
    if (len < 0) {
        flb_errno();
        return -1;
    }
    ctx->buf[len] = '\0';

    /* Process all messages in buffer */
    line = strtok(ctx->buf, "\n");
    while (line) {
        flb_trace("[in_statsd] received a line: '%s'", line);
        if (statsd_process_line(ctx, line) < 0) {
            flb_error("[in_statsd] failed to process line: '%s'", line);
            continue;
        }
        line = strtok(NULL, "\n");
    }
    return 0;
}

static int cb_statsd_collect(struct flb_input_instance *i_ins,
                             struct flb_config *config, void *data)
{
    struct flb_statsd *ctx = data;
    struct statsd_bucket *b;
    struct statsd_agg agg;
    struct mk_list *head;
    double interval;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    interval = ctx->interval_sec + ctx->interval_nsec / 10000000;

    mk_list_foreach(head, &ctx->buckets) {
        b = mk_list_entry(head, struct statsd_bucket, _head);

        msgpack_pack_array(&pck, 2);
        flb_pack_time_now(&pck);

        if (b->type == STATSD_TYPE_COUNTER) {
            msgpack_pack_map(&pck, 4);
            pack_string(&pck, "type");
            pack_string(&pck, "counter");
            pack_string(&pck, "bucket");
            pack_string(&pck, b->name);
            pack_string(&pck, "count");
            msgpack_pack_double(&pck, b->counter);
            pack_string(&pck, "rate");
            msgpack_pack_double(&pck, b->counter / interval);
            b->counter = 0;
        }
        else if (b->type == STATSD_TYPE_GAUGE) {
            msgpack_pack_map(&pck, 3);
            pack_string(&pck, "type");
            pack_string(&pck, "gauge");
            pack_string(&pck, "bucket");
            pack_string(&pck, b->name);
            pack_string(&pck, "value");
            msgpack_pack_double(&pck, b->gauge);
        }
        else if (b->type == STATSD_TYPE_TIMER) {
            msgpack_pack_map(&pck, b->timer_nr > 0 ? 10 : 3);
            pack_string(&pck, "type");
            pack_string(&pck, "timer");
            pack_string(&pck, "bucket");
            pack_string(&pck, b->name);

            bucket_describe_timer(b, &agg);
            if (agg.count > 0) {
                pack_string(&pck, "count");
                msgpack_pack_int(&pck, agg.count);
                pack_string(&pck, "lower");
                msgpack_pack_double(&pck, agg.lower);
                pack_string(&pck, "upper");
                msgpack_pack_double(&pck, agg.upper);
                pack_string(&pck, "median");
                msgpack_pack_double(&pck, agg.median);
                pack_string(&pck, "mean");
                msgpack_pack_double(&pck, agg.mean);
                pack_string(&pck, "sum");
                msgpack_pack_double(&pck, agg.sum);
                pack_string(&pck, "sum_squares");
                msgpack_pack_double(&pck, agg.sum_squares);
                pack_string(&pck, "std");
                msgpack_pack_double(&pck, agg.std);
            } else {
                pack_string(&pck, "count");
                msgpack_pack_int(&pck, 0);
            }
            bucket_clear_timer(b);
        }
        else if (b->type == STATSD_TYPE_SET) {
            msgpack_pack_map(&pck, 3);
            pack_string(&pck, "type");
            pack_string(&pck, "set");
            pack_string(&pck, "bucket");
            pack_string(&pck, b->name);
            pack_string(&pck, "count");
            msgpack_pack_int(&pck, b->set_nr);
            bucket_clear_set(b);
        }
    }
    flb_input_chunk_append_raw(i_ins, NULL, 0, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);
    return 0;
}

static int cb_statsd_init(struct flb_input_instance *i_ins,
                          struct flb_config *config, void *data)
{
    struct flb_statsd *ctx;
    const char *tmp;
    char *listen;
    int port;

    ctx = flb_calloc(1, sizeof(struct flb_statsd));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->buf = flb_malloc(MAX_PACKET_SIZE);
    if (!ctx->buf) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    ctx->i_ins = i_ins;

    /* Interval */
    tmp = flb_input_get_property("interval_sec", i_ins);
    if (tmp != NULL) {
        ctx->interval_sec = atoi(tmp);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    tmp = flb_input_get_property("interval_nsec", i_ins);
    if (tmp != NULL) {
        ctx->interval_nsec = atoi(tmp);
    }
    else {
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    /* Listening address */
    if (i_ins->host.listen) {
        listen = i_ins->host.listen;
    }
    else {
        listen = DEFAULT_LISTEN;
    }
    strncpy(ctx->listen, listen, sizeof(ctx->listen) - 1);

    /* Listening port */
    if (i_ins->host.port) {
        port = i_ins->host.port;
    }
    else {
        port = DEFAULT_PORT;
    }
    snprintf(ctx->port, sizeof(ctx->port), "%hu", port);

    /* Initialize buckets to hold metrics */
    mk_list_init(&ctx->buckets);

    /* Export plugin context */
    flb_input_set_context(i_ins, ctx);

    /*
     * Statsd server accepts metrics from UDP connections and outputs
     * aggregated statistics for every N second. So we need to set up
     * both (1) a UDP server and (2) a timer callback.
     */
    ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);
    if (ctx->server_fd == -1) {
        flb_error("[in_statsd] can't bind to %s:%s", ctx->listen, ctx->port);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    /* Set up the UDP connection callback */
    ctx->coll_fd = flb_input_set_collector_socket(i_ins, cb_statsd_receive,
                                                  ctx->server_fd, config);
    if (ctx->coll_fd == -1) {
        flb_error("[in_statsd] cannot set up connection callback ");
        flb_socket_close(ctx->server_fd);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    flb_info("[in_statsd] start UDP server on %s:%s", ctx->listen, ctx->port);

    /* Set up the timer callback */
    ctx->timer_fd = flb_input_set_collector_time(i_ins, cb_statsd_collect,
                                                 ctx->interval_sec,
                                                 ctx->interval_nsec, config);
    if (ctx->timer_fd == -1) {
        flb_error("[in_statsd] cannot set up a timer callback");
        return -1;
    }

    flb_info("[in_statsd] emit events every %i.%i sec", ctx->interval_sec,
             ctx->interval_nsec);

    return 0;
}

static void cb_statsd_pause(void *data, struct flb_config *config)
{
    struct flb_statsd *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->i_ins);
    flb_input_collector_pause(ctx->timer_fd, ctx->i_ins);
}

static void cb_statsd_resume(void *data, struct flb_config *config)
{
    struct flb_statsd *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->i_ins);
    flb_input_collector_resume(ctx->timer_fd, ctx->i_ins);
}

static int cb_statsd_exit(void *data, struct flb_config *config)
{
    struct flb_statsd *ctx = data;
    struct mk_list *head;
    struct mk_list *tmp;
    struct statsd_bucket *b;

    flb_input_collector_pause(ctx->timer_fd, ctx->i_ins);
    flb_input_collector_pause(ctx->coll_fd, ctx->i_ins);
    flb_socket_close(ctx->server_fd);

    /* Clean up buckets */
    mk_list_foreach_safe(head, tmp, &ctx->buckets) {
        b = mk_list_entry(head, struct statsd_bucket, _head);
        flb_sds_destroy(b->name);
        bucket_clear_timer(b);
        bucket_clear_set(b);
        flb_free(b);
    }

    flb_free(ctx->buf);
    flb_free(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_statsd_plugin = {
    .name         = "statsd",
    .description  = "statsd input plugin",
    .cb_init      = cb_statsd_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_statsd_collect,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_statsd_pause,
    .cb_resume    = cb_statsd_resume,
    .cb_exit      = cb_statsd_exit,
    .flags        = 0
};
