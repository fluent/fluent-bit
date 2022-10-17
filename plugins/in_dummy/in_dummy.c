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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include "in_dummy.h"

static int set_dummy_timestamp(msgpack_packer *mp_pck, struct flb_dummy *ctx)
{
    struct flb_time t;
    struct flb_time diff;
    struct flb_time dummy_time;
    int ret;

    if (ctx->data.log.base_timestamp == NULL) {
        ctx->data.log.base_timestamp = flb_malloc(sizeof(struct flb_time));
        if (!ctx->data.log.base_timestamp) {
            flb_errno();
            return -1;
        }

        flb_time_get(ctx->data.log.base_timestamp);
        ret = flb_time_append_to_msgpack(ctx->data.log.dummy_timestamp, mp_pck, 0);
    }
    else {
        flb_time_get(&t);
        flb_time_diff(&t, ctx->data.log.base_timestamp, &diff);
        flb_time_add(ctx->data.log.dummy_timestamp, &diff, &dummy_time);
        ret = flb_time_append_to_msgpack(&dummy_time, mp_pck, 0);
    }

    return ret;
}

static int gen_trace(struct flb_input_instance *ins, void *in_context)
{
    struct ctrace *ctr;
    struct ctrace_opts opts;
    struct ctrace_span *span_root;
    struct ctrace_span *span_child;
    struct ctrace_span_event *event;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;
    struct ctrace_scope_span *scope_span;
    struct ctrace_instrumentation_scope *instrumentation_scope;
    struct ctrace_link *link;
    struct ctrace_id *span_id;
    struct ctrace_id *trace_id;
    struct cfl_array *array;
    struct cfl_array *sub_array;
    struct cfl_kvlist *kv;
    struct flb_dummy *ctx = in_context;

    ctr_opts_init(&opts);

    /* ctrace context */
    ctr = ctr_create(&opts);
    if (!ctr) {
        return -1;
    }

    /* resource span */
    resource_span = ctr_resource_span_create(ctr);
    ctr_resource_span_set_schema_url(resource_span, "https://ctraces/resource_span_schema_url");

    /* create a 'resource' for the 'resource span' in question */
    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_dropped_attr_count(resource, 5);

    /* scope span */
    scope_span = ctr_scope_span_create(resource_span);
    ctr_scope_span_set_schema_url(scope_span, "https://ctraces/scope_span_schema_url");

    /* create an optional instrumentation scope */
    instrumentation_scope = ctr_instrumentation_scope_create("ctrace", "a.b.c", 3, NULL);
    ctr_scope_span_set_instrumentation_scope(scope_span, instrumentation_scope);

    /* generate a random trace_id */
    trace_id = ctr_id_create_random();

    /* generate a random ID for the new span */
    span_id = ctr_id_create_random();

    /* Create a root span */
    span_root = ctr_span_create(ctr, scope_span, "main", NULL);
    if (!span_root) {
        ctr_destroy(ctr);
        ctr_opts_exit(&opts);
        return -1;
    }

    /* assign the random ID */
    ctr_span_set_span_id_with_cid(span_root, span_id);

    /* set random trace_id */
    ctr_span_set_trace_id_with_cid(span_root, trace_id);

    /* add some attributes to the span */
    ctr_span_set_attribute_string(span_root, "agent", "Fluent Bit");
    ctr_span_set_attribute_int64(span_root, "year", 2022);
    ctr_span_set_attribute_bool(span_root, "open_source", CTR_TRUE);
    ctr_span_set_attribute_double(span_root, "temperature", 25.5);

    /* pack an array: create an array context by using the CFL api */
    array = cfl_array_create(4);
    cfl_array_append_string(array, "first");
    cfl_array_append_double(array, 2.0);
    cfl_array_append_bool(array, CFL_FALSE);

    sub_array = cfl_array_create(3);
    cfl_array_append_double(sub_array, 3.1);
    cfl_array_append_double(sub_array, 5.2);
    cfl_array_append_double(sub_array, 6.3);
    cfl_array_append_array(array, sub_array);

    /* add array to the attribute list */
    ctr_span_set_attribute_array(span_root, "my_array", array);

    /* event: add one event and set attributes to it */
    event = ctr_span_event_add(span_root, "connect to remote server");

    ctr_span_event_set_attribute_string(event, "syscall 1", "open()");
    ctr_span_event_set_attribute_string(event, "syscall 2", "connect()");
    ctr_span_event_set_attribute_string(event, "syscall 3", "write()");

    /* add a key/value pair list */
    kv = cfl_kvlist_create(1);
    cfl_kvlist_insert_string(kv, "language", "c");

    ctr_span_set_attribute_kvlist(span_root, "my-list", kv);

    /* create a child span */
    span_child = ctr_span_create(ctr, scope_span, "do-work", span_root);
    if (!span_child) {
        ctr_destroy(ctr);
        ctr_opts_exit(&opts);
        return -1;
    }

    /* set trace_id */
    ctr_span_set_trace_id_with_cid(span_child, trace_id);

    /* use span_root ID as parent_span_id */
    ctr_span_set_parent_span_id_with_cid(span_child, span_id);

    /* delete old span id and generate a new one */
    ctr_id_destroy(span_id);
    span_id = ctr_id_create_random();
    ctr_span_set_span_id_with_cid(span_child, span_id);

    /* destroy the IDs since is not longer needed */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    /* change span kind to client */
    ctr_span_kind_set(span_child, CTRACE_SPAN_CLIENT);

    /* create a Link (no valid IDs of course) */
    trace_id = ctr_id_create_random();
    span_id = ctr_id_create_random();

    link = ctr_link_create_with_cid(span_child, trace_id, span_id);
    ctr_link_set_trace_state(link, "aaabbbccc");
    ctr_link_set_dropped_attr_count(link, 2);

    /* delete IDs */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    ctx->data.trace = ctr;

    return 0;
}

static int gen_msg(struct flb_input_instance *ins, void *in_context, msgpack_sbuffer *mp_sbuf)
{
    size_t off = 0;
    size_t start = 0;
    char *pack;
    int pack_size;
    msgpack_unpacked result;
    msgpack_packer mp_pck;
    struct flb_dummy *ctx = in_context;

    pack = ctx->data.log.ref_msgpack;
    pack_size = ctx->data.log.ref_msgpack_size;
    msgpack_unpacked_init(&result);

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(mp_sbuf);
    msgpack_packer_init(&mp_pck, mp_sbuf, msgpack_sbuffer_write);

    while (msgpack_unpack_next(&result, pack, pack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            /* { map => val, map => val, map => val } */
            msgpack_pack_array(&mp_pck, 2);
            if (ctx->data.log.dummy_timestamp != NULL){
                set_dummy_timestamp(&mp_pck, ctx);
            }
            else {
                flb_pack_time_now(&mp_pck);
            }
            msgpack_pack_str_body(&mp_pck, pack + start, off - start);
        }
        start = off;
    }
    msgpack_unpacked_destroy(&result);

    return 0;
}

/* cb_collect callback */
static int in_dummy_collect(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    struct flb_dummy *ctx = in_context;
    msgpack_sbuffer mp_sbuf;

    if (ctx->samples > 0 && (ctx->samples_count >= ctx->samples)) {
        return -1;
    }

    if (strcasecmp(ctx->event_type, "log") == 0) {
        ins->event_type = FLB_INPUT_LOGS;

        if (ctx->fixed_timestamp == FLB_FALSE) {
            msgpack_sbuffer_init(&mp_sbuf);

            gen_msg(ins, in_context, &mp_sbuf);
            flb_input_log_append(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

            msgpack_sbuffer_destroy(&mp_sbuf);
        }
        else {
            flb_input_log_append(ins, NULL, 0, ctx->data.log.mp_sbuf.data, ctx->data.log.mp_sbuf.size);
        }
    }
    else if (strcasecmp(ctx->event_type, "trace") == 0) {
        flb_input_trace_append(ins, NULL, 0, ctx->data.trace);
    }

    if (ctx->samples > 0) {
        ctx->samples_count++;
    }
    return 0;
}

static int config_destroy(struct flb_dummy *ctx)
{

    if (strcasecmp(ctx->event_type, "log") == 0) {

        flb_free(ctx->data.log.ref_msgpack);
        flb_free(ctx->data.log.dummy_message);
        flb_free(ctx->data.log.dummy_timestamp);
        flb_free(ctx->data.log.base_timestamp);

        if (ctx->fixed_timestamp == FLB_TRUE) {
            msgpack_sbuffer_destroy(&ctx->data.log.mp_sbuf);
        }
    }

    if (strcasecmp(ctx->event_type, "trace") == 0) {
        ctr_destroy(ctx->data.trace);
    }

    flb_free(ctx);

    return 0;
}

static int configure_trace(struct flb_dummy *ctx,
                           struct flb_input_instance *in)
{
    int ret;

    ret = gen_trace(in, ctx);

    return ret;
}

static int configure_log(struct flb_dummy *ctx,
                         struct flb_input_instance *in)
{
    struct flb_time dummy_time;
    const char *msg;
    int root_type;
    int dummy_time_enabled = FLB_FALSE;
    int ret;

    ctx->data.log.dummy_message = NULL;
    ctx->data.log.dummy_message_len = 0;
    ctx->data.log.ref_msgpack = NULL;

    /* dummy timestamp */
    ctx->data.log.dummy_timestamp = NULL;
    ctx->data.log.base_timestamp = NULL;
    flb_time_zero(&dummy_time);

    if (ctx->data.log.start_time_sec >= 0 || ctx->data.log.start_time_nsec >= 0) {
        dummy_time_enabled = FLB_TRUE;
        if (ctx->data.log.start_time_sec >= 0) {
            dummy_time.tm.tv_sec = ctx->data.log.start_time_sec;
        }
        if (ctx->data.log.start_time_nsec >= 0) {
            dummy_time.tm.tv_nsec = ctx->data.log.start_time_nsec;
        }
    }

    if (dummy_time_enabled) {
        ctx->data.log.dummy_timestamp = flb_malloc(sizeof(struct flb_time));
        if (!ctx->data.log.dummy_timestamp) {
            flb_errno();
            return -1;
        }

        flb_time_copy(ctx->data.log.dummy_timestamp, &dummy_time);
    }

    /* handle it explicitly since we need to validate it is valid JSON */
    msg = flb_input_get_property("dummy", in);
    if (msg == NULL) {
        msg = DEFAULT_DUMMY_MESSAGE;
    }
    ret = flb_pack_json(msg, strlen(msg), &ctx->data.log.ref_msgpack,
                        &ctx->data.log.ref_msgpack_size, &root_type);
    if (ret == 0) {
        ctx->data.log.dummy_message = flb_strdup(msg);
        ctx->data.log.dummy_message_len = strlen(msg);
    }
    else {
        flb_plg_warn(ctx->ins, "data is incomplete. Use default string.");

        ctx->data.log.dummy_message = flb_strdup(DEFAULT_DUMMY_MESSAGE);
        ctx->data.log.dummy_message_len = strlen(ctx->data.log.dummy_message);

        ret = flb_pack_json(ctx->data.log.dummy_message,
                            ctx->data.log.dummy_message_len,
                            &ctx->data.log.ref_msgpack, &ctx->data.log.ref_msgpack_size,
                            &root_type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "unexpected error");
            return -1;
        }
    }

    if (ctx->fixed_timestamp == FLB_TRUE) {
        gen_msg(in, ctx, &ctx->data.log.mp_sbuf);
    }

    return ret;
}

/* Set plugin configuration */
static int configure(struct flb_dummy *ctx,
                     struct flb_input_instance *in,
                     struct timespec *tm)
{
    int  ret = -1;

    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* interval settings */
    tm->tv_sec  = 1;
    tm->tv_nsec = 0;

    if (ctx->rate > 1) {
        tm->tv_sec = 0;
        tm->tv_nsec = 1000000000 / ctx->rate;
    }

    if (strcmp(ctx->event_type, "log") == 0) {
        ret = configure_log(ctx, in);
    }
    else if (strcmp(ctx->event_type, "trace") == 0) {
        ret = configure_trace(ctx, in);
    }
    else {
        flb_plg_error(ctx->ins, "[in_dummy] invalid type '%s'", ctx->event_type);
        return -1;
    }

    return ret;
}

/* Initialize plugin */
static int in_dummy_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_dummy *ctx = NULL;
    struct timespec tm;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_dummy));
    if (ctx == NULL) {
        return -1;
    }
    ctx->ins = in;
    ctx->samples = 0;
    ctx->samples_count = 0;

    ctx->data.trace = NULL;

    /* Initialize head config */
    ret = configure(ctx, in, &tm);
    if (ret < 0) {
        config_destroy(ctx);
        flb_plg_error(ctx->ins, "[in_dummy] could not initialize plugin");
        return -1;
    }

    flb_input_set_context(in, ctx);
    ret = flb_input_set_collector_time(in,
                                       in_dummy_collect,
                                       tm.tv_sec,
                                       tm.tv_nsec, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for dummy input plugin");
        config_destroy(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static void in_dummy_pause(void *data, struct flb_config *config)
{
    struct flb_dummy *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_dummy_resume(void *data, struct flb_config *config)
{
    struct flb_dummy *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_dummy_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_dummy *ctx = data;

    config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "event_type", "log",
     0, FLB_TRUE, offsetof(struct flb_dummy, event_type),
     "Set the type of event to generate, options are: log or trace"
    },
   {
    FLB_CONFIG_MAP_INT, "samples", "0",
    0, FLB_TRUE, offsetof(struct flb_dummy, samples),
    "set a number of times to generate event."
   },
   {
    FLB_CONFIG_MAP_STR, "dummy", DEFAULT_DUMMY_MESSAGE,
    0, FLB_FALSE, 0,
    "set the sample record to be generated. It should be a JSON object."
   },
   {
    FLB_CONFIG_MAP_INT, "rate", "1",
    0, FLB_TRUE, offsetof(struct flb_dummy, rate),
    "set a number of events per second."
   },
   {
    FLB_CONFIG_MAP_INT, "start_time_sec", "-1",
    0, FLB_TRUE, offsetof(struct flb_dummy, data.log.start_time_sec),
    "set a dummy base timestamp in seconds."
   },
   {
    FLB_CONFIG_MAP_INT, "start_time_nsec", "-1",
    0, FLB_TRUE, offsetof(struct flb_dummy, data.log.start_time_nsec),
    "set a dummy base timestamp in nanoseconds."
   },
   {
    FLB_CONFIG_MAP_BOOL, "fixed_timestamp", "off",
    0, FLB_TRUE, offsetof(struct flb_dummy, fixed_timestamp),
    "used a fixed timestamp, allows the message to pre-generated once."
   },
   {0}
};


struct flb_input_plugin in_dummy_plugin = {
    .name         = "dummy",
    .description  = "Generate dummy data",
    .cb_init      = in_dummy_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_dummy_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_dummy_pause,
    .cb_resume    = in_dummy_resume,
    .cb_exit      = in_dummy_exit,
    .event_type  = FLB_INPUT_LOGS | FLB_INPUT_TRACES
};
