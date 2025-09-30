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
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_router.h>
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
        msgpack_pack_str(mp_pck, flb_sds_len(i->metrics->title));
        msgpack_pack_str_body(mp_pck, i->metrics->title, flb_sds_len(i->metrics->title));
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
        msgpack_pack_str(mp_pck, flb_sds_len(i->metrics->title));
        msgpack_pack_str_body(mp_pck, i->metrics->title, flb_sds_len(i->metrics->title));
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
        msgpack_pack_str(mp_pck, flb_sds_len(i->metrics->title));
        msgpack_pack_str_body(mp_pck, i->metrics->title, flb_sds_len(i->metrics->title));
        msgpack_sbuffer_write(mp_sbuf, buf, s);
        flb_free(buf);
    }

    return 0;
}

static int collect_metrics(struct flb_me *me)
{
    int ret;
    int keys;
    char *buf_data;
    size_t buf_size;
    struct flb_config *ctx = me->config;
    struct cmt *cmt;

    /*
     * msgpack buffer for old-style /v1/metrics
     * ----------------------------------------
     */
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

    /*
     * If the built-in HTTP server is enabled, push metrics and health checks
     * ---------------------------------------------------------------------
     */

#ifdef FLB_HAVE_HTTP_SERVER
    if (ctx->http_server == FLB_TRUE) {
        /* /v1/metrics (old) */
        flb_hs_push_pipeline_metrics(ctx->http_ctx, mp_sbuf.data, mp_sbuf.size);

        /* /v1/health */
        if (ctx->health_check == FLB_TRUE) {
            flb_hs_push_health_metrics(ctx->http_ctx, mp_sbuf.data, mp_sbuf.size);
        }

        /* /v2/metrics: retrieve a CMetrics context with internal metrics */
        cmt = flb_me_get_cmetrics(ctx);
        if (cmt) {
            /* encode context to msgpack */
            ret = cmt_encode_msgpack_create(cmt, &buf_data, &buf_size);
            if (ret == 0) {
                flb_hs_push_metrics(ctx->http_ctx, buf_data, buf_size);
                cmt_encode_msgpack_destroy(buf_data);
            }
            cmt_destroy(cmt);
        }
    }
#endif

    /* destroy msgpack buffer for old-style /v1/metrics */
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
    me = flb_calloc(1, sizeof(struct flb_me));
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

/* Export all metrics as CMetrics context */
struct cmt *flb_me_get_cmetrics(struct flb_config *ctx)
{
    int ret;
    struct mk_list *head, *processor_head;
    struct flb_input_instance *i;     /* inputs */
    struct flb_processor_unit *pu;    /* processors */
    struct flb_filter_instance *f, *pf;    /* filter */
    struct flb_output_instance *o;    /* output */
    struct cmt *cmt;

    cmt = cmt_create();
    if (!cmt) {
        return NULL;
    }

    /* Fluent Bit metrics */
    flb_metrics_fluentbit_add(ctx, cmt);

    if (ctx->storage_metrics == FLB_TRUE) {
        /*
         * Storage metrics are updated in two places:
         *
         * - global metrics: updated by using flb_storage_metrics_update()
         * - input: flb_storage callback update the metrics automatically every 5 seconds
         *
         * In this part, we only take care about the global storage metrics.
         */
        flb_storage_metrics_update(ctx, ctx->storage_metrics_ctx);
        ret = cmt_cat(cmt, ctx->storage_metrics_ctx->cmt);
        if (ret == -1) {
            flb_error("[metrics exporter] could not append global storage_metrics");
            cmt_destroy(cmt);
            return NULL;
        }
    }

    if (ctx->router && ctx->router->cmt) {
        ret = cmt_cat(cmt, ctx->router->cmt);
        if (ret == -1) {
            flb_error("[metrics exporter] could not append routing metrics");
            cmt_destroy(cmt);
            return NULL;
        }
        printf("debug after appending routing metrics\n");
        flb_sds_t t= cmt_encode_text_create(cmt);
        printf("%s\n", t);
        cmt_encode_text_destroy(t);
    }

    /* Pipeline metrics: input, filters, outputs */
    mk_list_foreach(head, &ctx->inputs) {
        i = mk_list_entry(head, struct flb_input_instance, _head);
        ret = cmt_cat(cmt, i->cmt);
        if (ret == -1) {
            flb_error("[metrics exporter] could not append metrics from %s",
                      flb_input_name(i));
            cmt_destroy(cmt);
            return NULL;
        }

        mk_list_foreach(processor_head, &i->processor->logs) {
            pu = mk_list_entry(processor_head, struct flb_processor_unit, _head);
            if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
                pf = (struct flb_filter_instance *) pu->ctx;
                ret = cmt_cat(cmt, pf->cmt);
                if (ret == -1) {
                    flb_error("[metrics exporter] could not append metrics from %s", flb_filter_name(pf));
                    cmt_destroy(cmt);
                    return NULL;
                }
            }
        }
    }

    mk_list_foreach(head, &ctx->filters) {
        f = mk_list_entry(head, struct flb_filter_instance, _head);
        ret = cmt_cat(cmt, f->cmt);
        if (ret == -1) {
            flb_error("[metrics exporter] could not append metrics from %s",
                      flb_filter_name(f));
            cmt_destroy(cmt);
            return NULL;
        }
    }

    mk_list_foreach(head, &ctx->outputs) {
        o = mk_list_entry(head, struct flb_output_instance, _head);
        ret = cmt_cat(cmt, o->cmt);
        if (ret == -1) {
            flb_error("[metrics exporter] could not append metrics from %s",
                      flb_output_name(o));
            cmt_destroy(cmt);
            return NULL;
        }

        mk_list_foreach(processor_head, &o->processor->logs) {
            pu = mk_list_entry(processor_head, struct flb_processor_unit, _head);
            if (pu->unit_type == FLB_PROCESSOR_UNIT_FILTER) {
                pf = (struct flb_filter_instance *) pu->ctx;
                ret = cmt_cat(cmt, pf->cmt);
                if (ret == -1) {
                    flb_error("[metrics exporter] could not append metrics from %s", flb_filter_name(pf));
                    cmt_destroy(cmt);
                    return NULL;
                }
            }
        }
    }

    return cmt;
}
