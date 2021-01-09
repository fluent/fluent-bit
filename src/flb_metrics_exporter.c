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

/*
 * Metrics exporter go around each Fluent Bit subsystem and collect metrics
 * in a fixed interval of time. This operation is atomic and happens as one
 * event handled by the main event loop.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_metrics_exporter.h>

static int collect_inputs(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                          struct flb_config *ctx)
{
    int total = 0;
    size_t s;
    char *buf;
    struct mk_list *head;
    struct flb_input_instance *i;

    msgpack_pack_str(mp_pck, 5);
    msgpack_pack_str_body(mp_pck, "input", 5);

    mk_list_foreach(head, &ctx->inputs) {
        i = mk_list_entry(head, struct flb_input_instance, _head);
        if (!i->metrics) {
            continue;
        }
        total++; /* FIXME: keep total number in cache */
    }

    msgpack_pack_map(mp_pck, total);
    mk_list_foreach(head, &ctx->inputs) {
        i = mk_list_entry(head, struct flb_input_instance, _head);
        if (!i->metrics) {
            continue;
        }

        flb_metrics_dump_values(&buf, &s, i->metrics);
        msgpack_pack_str(mp_pck, i->metrics->title_len);
        msgpack_pack_str_body(mp_pck, i->metrics->title, i->metrics->title_len);
        msgpack_sbuffer_write(mp_sbuf, buf, s);
        flb_free(buf);
    }

    return 0;
}

static int collect_filters(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                           struct flb_config *ctx)
{
    int total = 0;
    size_t s;
    char *buf;
    struct mk_list *head;
    struct flb_filter_instance *i;

    msgpack_pack_str(mp_pck, 6);
    msgpack_pack_str_body(mp_pck, "filter", 6);

    mk_list_foreach(head, &ctx->filters) {
        i = mk_list_entry(head, struct flb_filter_instance, _head);
        if (!i->metrics) {
            continue;
        }
        total++;
    }

    msgpack_pack_map(mp_pck, total);
    mk_list_foreach(head, &ctx->filters) {
        i = mk_list_entry(head, struct flb_filter_instance, _head);
        if (!i->metrics) {
            continue;
        }

        flb_metrics_dump_values(&buf, &s, i->metrics);
        msgpack_pack_str(mp_pck, i->metrics->title_len);
        msgpack_pack_str_body(mp_pck, i->metrics->title, i->metrics->title_len);
        msgpack_sbuffer_write(mp_sbuf, buf, s);
        flb_free(buf);
    }

    return 0;
}

static int collect_outputs(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                           struct flb_config *ctx)
{
    int total = 0;
    size_t s;
    char *buf;
    struct mk_list *head;
    struct flb_output_instance *i;

    msgpack_pack_str(mp_pck, 6);
    msgpack_pack_str_body(mp_pck, "output", 6);

    mk_list_foreach(head, &ctx->outputs) {
        i = mk_list_entry(head, struct flb_output_instance, _head);
        if (!i->metrics) {
            continue;
        }
        total++; /* FIXME: keep total number in cache */
    }

    msgpack_pack_map(mp_pck, total);
    mk_list_foreach(head, &ctx->outputs) {
        i = mk_list_entry(head, struct flb_output_instance, _head);
        if (!i->metrics) {
            continue;
        }

        flb_metrics_dump_values(&buf, &s, i->metrics);
        msgpack_pack_str(mp_pck, i->metrics->title_len);
        msgpack_pack_str_body(mp_pck, i->metrics->title, i->metrics->title_len);
        msgpack_sbuffer_write(mp_sbuf, buf, s);
        flb_free(buf);
    }

    return 0;
}

static int collect_metrics(struct flb_me *me)
{
    int keys;
    struct flb_config *ctx = me->config;

    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    keys = 3; /* input, filter, output */
    msgpack_pack_map(&mp_pck, keys);

    /* Collect metrics from input instances */
    collect_inputs(&mp_sbuf, &mp_pck, me->config);
    collect_filters(&mp_sbuf, &mp_pck, me->config);
    collect_outputs(&mp_sbuf, &mp_pck, me->config);

#ifdef FLB_HAVE_HTTP_SERVER
    if (ctx->http_server == FLB_TRUE) {
        flb_hs_push_pipeline_metrics(ctx->http_ctx, mp_sbuf.data, mp_sbuf.size);
    }
#endif
    msgpack_sbuffer_destroy(&mp_sbuf);


    return 0;
}

/* Create metrics exporter context */
struct flb_me *flb_me_create(struct flb_config *ctx)
{
    int fd;
    struct mk_event *event;
    struct flb_me *me;

    /* Context */
    me = flb_malloc(sizeof(struct flb_me));
    if (!me) {
        flb_errno();
        return NULL;
    }
    me->config = ctx;

    /* Initialize event loop context */
    event = &me->event;
    MK_EVENT_ZERO(event);

    /* Run every one second */
    fd = mk_event_timeout_create(ctx->evl, 1, 0, &me->event);
    if (fd == -1) {
        flb_error("[metrics_exporter] registration failed");
        flb_free(me);
        return NULL;
    }
    me->fd = fd;

    return me;

}

/* Handle the event loop notification: "it's time to collect metrics" */
int flb_me_fd_event(int fd, struct flb_me *me)
{
    if (fd != me->fd) {
        return -1;
    }

    flb_utils_timer_consume(fd);
    collect_metrics(me);

    return 0;
}

int flb_me_destroy(struct flb_me *me)
{
    mk_event_timeout_destroy(me->config->evl, &me->event);
    flb_free(me);
    return 0;
}
