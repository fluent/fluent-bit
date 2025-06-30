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

#include <fcntl.h>

#include <msgpack.h>
#include <chunkio/chunkio.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_chunk_trace.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_kv.h>


/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in);

/****************************************************************************/
/* To avoid double frees when enabling and disabling tracing as well        */
/* as avoiding race conditions when stopping fluent-bit while someone is    */
/* toggling tracing via the HTTP API this set of APIS with a mutex lock     */
/* is used:                                                                 */
/*   * flb_chunk_trace_to_be_destroyed - query to see if the trace context  */
/*     is slated to be freed                                                */
/*   * flb_chunk_trace_set_destroy - set the trace context to be destroyed  */
/*     once all chunks are freed (executed in flb_chunk_trace_destroy).     */
/*   * flb_chunk_trace_has_chunks - see if there are still chunks using     */
/*     using the tracing context                                            */
/*   * flb_chunk_trace_add - increment the traces chunk count               */
/*   * flb_chunk_trace_sub - decrement the traces chunk count               */
/****************************************************************************/
static inline int flb_chunk_trace_to_be_destroyed(struct flb_chunk_trace_context *ctxt)
{
    int ret = FLB_FALSE;

    ret = (ctxt->to_destroy == 1 ? FLB_TRUE : FLB_FALSE);
    return ret;
}

static inline int flb_chunk_trace_has_chunks(struct flb_chunk_trace_context *ctxt)
{
    int ret = FLB_FALSE;

    ret = ((ctxt->chunks > 0) ? FLB_TRUE : FLB_FALSE);
    return ret;
}

static inline void flb_chunk_trace_add(struct flb_chunk_trace_context *ctxt)
{
    ctxt->chunks++;
}

static inline void flb_chunk_trace_sub(struct flb_chunk_trace_context *ctxt)
{
    ctxt->chunks--;
}

static inline void flb_chunk_trace_set_destroy(struct flb_chunk_trace_context *ctxt)
{
    ctxt->to_destroy = 1;
}

static struct flb_output_instance *find_calyptia_output_instance(struct flb_config *config)
{
    struct mk_list *head = NULL;
    struct flb_output_instance *output = NULL;

    mk_list_foreach(head, &config->outputs) {
        output = mk_list_entry(head, struct flb_output_instance, _head);
        if (strcmp(output->p->name, "calyptia") == 0) {
            return output;
        }
    }
    return NULL;
}

static void trace_pipeline_stop(struct flb_chunk_pipeline_context *pipeline)
{
    flb_sds_destroy(pipeline->output_name);

    flb_trace("stop the pipeline");
    flb_stop(pipeline->flb);

    flb_trace("signaling pipeline thread to stop");
    pthread_mutex_lock(&pipeline->lock);
    pthread_cond_signal(&pipeline->cond);
    pthread_mutex_unlock(&pipeline->lock);

    flb_trace("joining pipeline thread...");

    pthread_join(pipeline->thread, NULL);
    flb_destroy(pipeline->flb);
}

static void trace_pipeline_shutdown(struct flb_chunk_pipeline_context *pipeline)
{
    flb_input_pause_all(pipeline->flb->config);
}

static void trace_pipeline_wait(struct flb_chunk_pipeline_context *pipeline)
{
    int i;

    /* waiting for all tasks to end is key to safely stopping and destroying */
    /* the fluent-bit pipeline. */
    for (i = 0; i < 5 && flb_task_running_count(pipeline->flb->config) > 0; i++) {
        usleep(10 * 1000);
    }
}

static void trace_chunk_context_destroy(struct flb_chunk_trace_context *ctxt)
{
    if (flb_chunk_trace_has_chunks(ctxt) == FLB_TRUE) {
        flb_chunk_trace_set_destroy(ctxt);
        trace_pipeline_shutdown(&ctxt->pipeline);
        return;
    }

    /* pause all inputs, then destroy the input storage. */
    trace_pipeline_shutdown(&ctxt->pipeline);
    trace_pipeline_wait(&ctxt->pipeline);

    flb_sds_destroy(ctxt->trace_prefix);
    trace_pipeline_stop(&ctxt->pipeline);
    flb_free(ctxt);
}

void flb_chunk_trace_context_destroy(void *input)
{
    struct flb_input_instance *in = (struct flb_input_instance *)input;
    pthread_mutex_lock(&in->chunk_trace_lock);
    if (in->chunk_trace_ctxt != NULL) {
        trace_chunk_context_destroy(in->chunk_trace_ctxt);
        in->chunk_trace_ctxt = NULL;
    }
    pthread_mutex_unlock(&in->chunk_trace_lock);
}

static void *trace_chunk_pipeline_thread(void *arg)
{
    int ret;
    struct flb_chunk_pipeline_context *ctx = (struct flb_chunk_pipeline_context *)arg;
    struct flb_input_instance *input = NULL;
    struct flb_output_instance *output = NULL;
    struct mk_list *head = NULL;
    struct flb_kv *prop = NULL;

    flb_trace("[pipeline_thead]: waiting for start lock");
    pthread_mutex_lock(&ctx->lock);
    flb_trace("[pipeline_thead]: waited for start lock");

    ctx->flb = flb_create();
    if (ctx->flb == NULL) {
        flb_errno();
        goto error_lock;
    }

    flb_service_set(ctx->flb, "flush", "1", "grace", "1", NULL);

    input = (void *)flb_input_new(ctx->flb->config, "emitter", NULL, FLB_FALSE);
    if (input == NULL) {
        flb_error("could not load trace emitter");
        goto error_flb;
    }
    input->is_threaded = FLB_TRUE;

    ret = flb_input_set_property(input, "alias", "trace-emitter");
    if (ret != 0) {
        flb_error("unable to set alias for trace emitter");
        goto error_input;
    }

    ret = flb_input_set_property(input, "ring_buffer_size", "4096");
    if (ret != 0) {
        flb_error("unable to set ring buffer size for trace emitter");
        goto error_input;
    }

    output = flb_output_new(ctx->flb->config, ctx->output_name, ctx->data, 1);
    if (output == NULL) {
        flb_error("could not create trace output");
        goto error_input;
    }

    if (ctx->props != NULL) {
        mk_list_foreach(head, ctx->props) {
            prop = mk_list_entry(head, struct flb_kv, _head);
            flb_output_set_property(output, prop->key, prop->val);
        }
    }

    ret = flb_router_connect_direct(input, output);
    if (ret != 0) {
        flb_error("unable to route traces");
        goto error_output;
    }

    ctx->output = (void *)output;
    ctx->input = (void *)input;

    flb_trace("[pipeline_thead]: start pipeline in thread");

    if (flb_start(ctx->flb) != 0) {
        flb_error("[pipeline_thead]: unable to start pipeline");
        goto error_output;
    }

    /* signal that we have finally started and we can begin waiting to exit.*/
    if (pthread_cond_signal(&ctx->cond) != 0) {
        errno = ret;
        flb_errno();
        flb_error("[pipeline_thead]: unable to signal start of pipeline");
        goto error_start;
    }

    if (pthread_mutex_unlock(&ctx->lock) != 0) {
        errno = ret;
        flb_errno();
        flb_error("[pipeline_thead]: unable to unlock mutex at start of pipeline");
        goto error_start;
    }

    /* simply wait here until the trace context is destroyed. */
    flb_trace("[pipeline_thead]: wait for exit of pipeline thread");

    if ((ret = pthread_mutex_lock(&ctx->lock)) != 0) {
        errno = ret;
        flb_errno();
        flb_error("[pipeline_thread]: unable to lock when waiting");
        goto error_start;
    }

    if ((ret = pthread_cond_wait(&ctx->cond, &ctx->lock)) != 0) {
        errno = ret;
        flb_errno();
        flb_error("[pipeline_thread]: unable to wait for exit");
        goto error_start;
    }

    pthread_mutex_unlock(&ctx->lock);

    flb_trace("[pipeline_thead]: exit trace pipeline thread");
    return NULL;

error_start:
    flb_stop(ctx->flb);
error_output:
    flb_output_instance_destroy(output);
error_input:
    flb_input_instance_destroy(input);
error_flb:
    flb_destroy(ctx->flb);
error_lock:
    pthread_mutex_unlock(&ctx->lock);
    flb_trace("[pipeline_thead]: error: exit trace pipeline thread.");
    return NULL;
}

static int trace_pipeline_start(struct flb_chunk_pipeline_context *pipeline)
{
    int rc;

    flb_trace("start pipeline thread");
    /* we open the lock before starting the pipeline thread so it will
     * wait for us to wait for it...
     */
    if (pthread_mutex_lock(&pipeline->lock) != 0) {
        flb_errno();
        return FLB_FALSE;
    }

    errno = 0;
    rc = pthread_create(&pipeline->thread, NULL, trace_chunk_pipeline_thread,
                   (void *)pipeline);

    if (rc != 0) {

        /* store the return value in errno if it is zero since . */
        if (errno == 0) {
            errno = rc;
        }

        flb_errno();
        return FLB_FALSE;
    }

    flb_trace("waiting for pipeline to start");
    rc = pthread_cond_wait(&pipeline->cond, &pipeline->lock);

    if (rc != 0) {

        /* store the return value in errno if it is zero since . */
        if (errno == 0) {
            errno = rc;
        }

        flb_errno();
        return FLB_FALSE;
    }

    rc = pthread_mutex_unlock(&pipeline->lock);

    if (rc != 0) {

        /* store the return value in errno if it is zero since . */
        if (errno == 0) {
            errno = rc;
        }

        flb_errno();
        return FLB_FALSE;
    }

    flb_trace("pipeline thread has started");

    return FLB_TRUE;
}

static int trace_pipeline_init(struct flb_chunk_pipeline_context *pipeline,
                           struct flb_config *config, const char *output_name,
                           void *data, struct mk_list *props)
{
    struct flb_output_instance *calyptia = NULL;

    pipeline->data = data;
    pipeline->output_name = flb_sds_create(output_name);

    if (strcmp(pipeline->output_name, "calyptia") == 0) {
        calyptia = find_calyptia_output_instance(config);
        if (calyptia == NULL) {
            flb_error("unable to find calyptia output instance");
            flb_sds_destroy(pipeline->output_name);
            return FLB_FALSE;
        }
        pipeline->props = &calyptia->properties;
    }
    else if (props != NULL) {
        pipeline->props = props;
    }

    pthread_mutex_init(&pipeline->lock, NULL);
    pthread_cond_init(&pipeline->cond, NULL);

    return trace_pipeline_start(pipeline);
}

struct flb_chunk_trace_context *flb_chunk_trace_context_new(void *trace_input,
                                                            const char *output_name,
                                                            const char *trace_prefix,
                                                            void *data, struct mk_list *props)
{
    struct flb_input_instance *in = (struct flb_input_instance *)trace_input;
    struct flb_config *config = in->config;
    struct flb_chunk_trace_context *ctx = NULL;

    if (config->enable_chunk_trace == FLB_FALSE) {
        flb_warn("[chunk trace] enable chunk tracing via the configuration or "
                 " command line to be able to activate tracing.");
        return NULL;
    }

    pthread_mutex_lock(&in->chunk_trace_lock);

    if (in->chunk_trace_ctxt) {
        trace_chunk_context_destroy(in->chunk_trace_ctxt);
    }

    ctx = flb_calloc(1, sizeof(struct flb_chunk_trace_context));
    if (ctx == NULL) {
        flb_errno();
        pthread_mutex_unlock(&in->chunk_trace_lock);
        return NULL;
    }

    if (trace_pipeline_init(&ctx->pipeline, config, output_name, data, props) == FLB_FALSE) {
        flb_error("unable to initialize chunk trace pipeline");
        flb_free(ctx);
        pthread_mutex_unlock(&in->chunk_trace_lock);
        return NULL;
    }

    ctx->input = ctx->pipeline.input;
    ctx->trace_prefix = flb_sds_create(trace_prefix);

    in->chunk_trace_ctxt = ctx;
    pthread_mutex_unlock(&in->chunk_trace_lock);
    return ctx;
}

struct flb_chunk_trace *flb_chunk_trace_new(struct flb_input_chunk *chunk)
{
    struct flb_chunk_trace *trace = NULL;
    struct flb_input_instance *f_ins = (struct flb_input_instance *)chunk->in;

    pthread_mutex_lock(&f_ins->chunk_trace_lock);

    if (flb_chunk_trace_to_be_destroyed(f_ins->chunk_trace_ctxt) == FLB_TRUE) {
        pthread_mutex_unlock(&f_ins->chunk_trace_lock);
        return NULL;
    }

    trace = flb_calloc(1, sizeof(struct flb_chunk_trace));
    if (trace == NULL) {
        flb_errno();
        pthread_mutex_unlock(&f_ins->chunk_trace_lock);
        return NULL;
    }

    trace->ctxt = f_ins->chunk_trace_ctxt;
    flb_chunk_trace_add(trace->ctxt);

    trace->trace_id = flb_sds_create("");
    if (flb_sds_printf(&trace->trace_id, "%s%d", trace->ctxt->trace_prefix,
                  trace->ctxt->trace_count++) == NULL) {
        pthread_mutex_unlock(&f_ins->chunk_trace_lock);
        flb_sds_destroy(trace->trace_id);
        flb_free(trace);
        return NULL;
    }

    trace->ic = chunk;

    pthread_mutex_unlock(&f_ins->chunk_trace_lock);
    return trace;
}

void flb_chunk_trace_destroy(struct flb_chunk_trace *trace)
{
    pthread_mutex_lock(&trace->ic->in->chunk_trace_lock);
    flb_chunk_trace_sub(trace->ctxt);

    /* check to see if we need to free the trace context. */
    if (flb_chunk_trace_has_chunks(trace->ctxt) == FLB_FALSE &&
        flb_chunk_trace_to_be_destroyed(trace->ctxt) == FLB_TRUE) {
        trace_chunk_context_destroy(trace->ctxt);
    }
    else if (flb_chunk_trace_has_chunks(trace->ctxt) == FLB_TRUE &&
        flb_chunk_trace_to_be_destroyed(trace->ctxt) == FLB_TRUE) {
    }
    pthread_mutex_unlock(&trace->ic->in->chunk_trace_lock);

    flb_sds_destroy(trace->trace_id);
    flb_free(trace);
}

int flb_chunk_trace_context_set_limit(void *input, int limit_type, int limit_arg)
{
    struct flb_input_instance *in = (struct flb_input_instance *)input;
    struct flb_chunk_trace_context *ctxt = NULL;
    struct flb_time tm;

    pthread_mutex_lock(&in->chunk_trace_lock);

    ctxt = in->chunk_trace_ctxt;
    if (ctxt == NULL) {
        pthread_mutex_unlock(&in->chunk_trace_lock);
        return -1;
    }

    switch(limit_type) {
    case FLB_CHUNK_TRACE_LIMIT_TIME:
        flb_time_get(&tm);
        ctxt->limit.type = FLB_CHUNK_TRACE_LIMIT_TIME;
        ctxt->limit.seconds_started = tm.tm.tv_sec;
        ctxt->limit.seconds = limit_arg;

        pthread_mutex_unlock(&in->chunk_trace_lock);
        return 0;
    case FLB_CHUNK_TRACE_LIMIT_COUNT:
        ctxt->limit.type = FLB_CHUNK_TRACE_LIMIT_COUNT;
        ctxt->limit.count = limit_arg;

        pthread_mutex_unlock(&in->chunk_trace_lock);
        return 0;
    }

    pthread_mutex_unlock(&in->chunk_trace_lock);
    return -1;
}

int flb_chunk_trace_context_hit_limit(void *input)
{
    struct flb_input_instance *in = (struct flb_input_instance *)input;
    struct flb_time tm;
    struct flb_chunk_trace_context *ctxt = NULL;

    pthread_mutex_lock(&in->chunk_trace_lock);

    ctxt = in->chunk_trace_ctxt;
    if (ctxt == NULL) {
        pthread_mutex_unlock(&in->chunk_trace_lock);
        return FLB_FALSE;
    }

    switch(ctxt->limit.type) {
    case FLB_CHUNK_TRACE_LIMIT_TIME:
        flb_time_get(&tm);
        if ((tm.tm.tv_sec - ctxt->limit.seconds_started) > ctxt->limit.seconds) {
            pthread_mutex_unlock(&in->chunk_trace_lock);
            return FLB_TRUE;
        }
        return FLB_FALSE;
    case FLB_CHUNK_TRACE_LIMIT_COUNT:
        if (ctxt->limit.count <= ctxt->trace_count) {
            pthread_mutex_unlock(&in->chunk_trace_lock);
            return FLB_TRUE;
        }
        pthread_mutex_unlock(&in->chunk_trace_lock);
        return FLB_FALSE;
    }
    pthread_mutex_unlock(&in->chunk_trace_lock);
    return FLB_FALSE;
}

void flb_chunk_trace_do_input(struct flb_input_chunk *ic)
{
    pthread_mutex_lock(&ic->in->chunk_trace_lock);
    if (ic->in->chunk_trace_ctxt == NULL) {
        pthread_mutex_unlock(&ic->in->chunk_trace_lock);
        return;
    }
    pthread_mutex_unlock(&ic->in->chunk_trace_lock);

    if (ic->trace == NULL) {
        ic->trace = flb_chunk_trace_new(ic);
    }

    if (ic->trace) {
        flb_chunk_trace_input(ic->trace);
        if (flb_chunk_trace_context_hit_limit(ic->in) == FLB_TRUE) {
            flb_chunk_trace_context_destroy(ic->in);
        }
    }
}

int flb_chunk_trace_input(struct flb_chunk_trace *trace)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *record = NULL;
    char *buf = NULL;
    size_t buf_size;
    struct flb_time tm;
    struct flb_time tm_end;
    struct flb_input_instance *input = (struct flb_input_instance *)trace->ic->in;
    int rc = -1;
    size_t off = 0;
    flb_sds_t tag = flb_sds_create("trace");
    int records = 0;


    /* initiailize start time */
    flb_time_get(&tm);
    flb_time_get(&tm_end);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    cio_chunk_get_content(trace->ic->chunk, &buf, &buf_size);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    if (input->alias != NULL) {
        msgpack_pack_map(&mp_pck, 7);
    }
    else {
        msgpack_pack_map(&mp_pck, 6);
    }

    msgpack_pack_str_with_body(&mp_pck, "type", 4);
    msgpack_pack_int(&mp_pck, FLB_CHUNK_TRACE_TYPE_INPUT);

    msgpack_pack_str_with_body(&mp_pck, "trace_id", strlen("trace_id"));
    msgpack_pack_str_with_body(&mp_pck, trace->trace_id, strlen(trace->trace_id));

    msgpack_pack_str_with_body(&mp_pck, "plugin_instance", strlen("plugin_instance"));
    msgpack_pack_str_with_body(&mp_pck, input->name, strlen(input->name));

    if (input->alias != NULL) {
        msgpack_pack_str_with_body(&mp_pck, "plugin_alias", strlen("plugin_alias"));
        msgpack_pack_str_with_body(&mp_pck, input->alias, strlen(input->alias));
    }

    msgpack_pack_str_with_body(&mp_pck, "records", strlen("records"));

    if (buf_size > 0) {
        do {
            rc = msgpack_unpack_next(&result, buf, buf_size, &off);
            if (rc != MSGPACK_UNPACK_SUCCESS) {
                flb_error("unable to unpack record");
                goto sbuffer_error;
            }
            records++;
        } while (rc == MSGPACK_UNPACK_SUCCESS && off < buf_size);

        msgpack_pack_array(&mp_pck, records);

        off = 0;
        do {
            rc = msgpack_unpack_next(&result, buf, buf_size, &off);
            if (rc != MSGPACK_UNPACK_SUCCESS) {
                flb_error("unable to unpack record");
                goto sbuffer_error;
            }
            flb_time_pop_from_msgpack(&tm, &result, &record);

            msgpack_pack_map(&mp_pck, 2);
            msgpack_pack_str_with_body(&mp_pck, "timestamp", strlen("timestamp"));
            flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
            msgpack_pack_str_with_body(&mp_pck, "record", strlen("record"));
            msgpack_pack_object(&mp_pck, *record);

        } while (rc == MSGPACK_UNPACK_SUCCESS && off < buf_size);
    }

    msgpack_pack_str_with_body(&mp_pck, "start_time", strlen("start_time"));
    flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, "end_time", strlen("end_time"));
    flb_time_append_to_msgpack(&tm_end, &mp_pck, FLB_TIME_ETFMT_INT);
    flb_input_log_append(trace->ctxt->input,
                         tag, flb_sds_len(tag),
                         mp_sbuf.data, mp_sbuf.size);
    // in_emitter_add_record(tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size,
    //                      trace->ctxt->input);
sbuffer_error:
    flb_sds_destroy(tag);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
    return rc;
}

int flb_chunk_trace_pre_output(struct flb_chunk_trace *trace)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *record = NULL;
    char *buf = NULL;
    size_t buf_size;
    struct flb_time tm;
    struct flb_time tm_end;
    struct flb_input_instance *input = (struct flb_input_instance *)trace->ic->in;
    int rc = -1;
    size_t off = 0;
    flb_sds_t tag = flb_sds_create("trace");
    int records = 0;


    /* initiailize start time */
    flb_time_get(&tm);
    flb_time_get(&tm_end);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    cio_chunk_get_content(trace->ic->chunk, &buf, &buf_size);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    if (input->alias != NULL) {
        msgpack_pack_map(&mp_pck, 7);
    }
    else {
        msgpack_pack_map(&mp_pck, 6);
    }

    msgpack_pack_str_with_body(&mp_pck, "type", 4);
    msgpack_pack_int(&mp_pck, FLB_CHUNK_TRACE_TYPE_PRE_OUTPUT);

    msgpack_pack_str_with_body(&mp_pck, "trace_id", strlen("trace_id"));
    msgpack_pack_str_with_body(&mp_pck, trace->trace_id, strlen(trace->trace_id));

    msgpack_pack_str_with_body(&mp_pck, "plugin_instance", strlen("plugin_instance"));
    msgpack_pack_str_with_body(&mp_pck, input->name, strlen(input->name));

    if (input->alias != NULL) {
        msgpack_pack_str_with_body(&mp_pck, "plugin_alias", strlen("plugin_alias"));
        msgpack_pack_str_with_body(&mp_pck, input->alias, strlen(input->alias));
    }

    msgpack_pack_str_with_body(&mp_pck, "records", strlen("records"));

    if (buf_size > 0) {
        do {
            rc = msgpack_unpack_next(&result, buf, buf_size, &off);
            if (rc != MSGPACK_UNPACK_SUCCESS) {
                flb_error("unable to unpack record");
                goto sbuffer_error;
            }
            records++;
        } while (rc == MSGPACK_UNPACK_SUCCESS && off < buf_size);

        msgpack_pack_array(&mp_pck, records);
        off = 0;
        do {
            rc = msgpack_unpack_next(&result, buf, buf_size, &off);
            if (rc != MSGPACK_UNPACK_SUCCESS) {
                flb_error("unable to unpack record");
                goto sbuffer_error;
            }
            flb_time_pop_from_msgpack(&tm, &result, &record);

            msgpack_pack_map(&mp_pck, 2);
            msgpack_pack_str_with_body(&mp_pck, "timestamp", strlen("timestamp"));
            flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
            msgpack_pack_str_with_body(&mp_pck, "record", strlen("record"));
            msgpack_pack_object(&mp_pck, *record);

        } while (rc == MSGPACK_UNPACK_SUCCESS && off < buf_size);
    }

    msgpack_pack_str_with_body(&mp_pck, "start_time", strlen("start_time"));
    flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, "end_time", strlen("end_time"));
    flb_time_append_to_msgpack(&tm_end, &mp_pck, FLB_TIME_ETFMT_INT);
    flb_input_log_append(trace->ctxt->input,
                         tag, flb_sds_len(tag),
                         mp_sbuf.data, mp_sbuf.size);
    // in_emitter_add_record(tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size,
    //                      trace->ctxt->input);
sbuffer_error:
    flb_sds_destroy(tag);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
    return rc;
}

int flb_chunk_trace_filter(struct flb_chunk_trace *tracer, void *pfilter, struct flb_time *tm_start, struct flb_time *tm_end, char *buf, size_t buf_size)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *record = NULL;
    int rc = -1;
    struct flb_filter_instance *filter = (struct flb_filter_instance *)pfilter;
    flb_sds_t tag = flb_sds_create("trace");
    struct flb_time tm;
    size_t off = 0;
    int records = 0;


    if (tracer == NULL) {
        goto tracer_error;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    if (filter->alias == NULL) {
        msgpack_pack_map(&mp_pck, 6);
    }
    else {
        msgpack_pack_map(&mp_pck, 7);
    }

    msgpack_pack_str_with_body(&mp_pck, "type", strlen("type"));
    rc = msgpack_pack_int(&mp_pck, FLB_CHUNK_TRACE_TYPE_FILTER);
    if (rc == -1) {
        goto sbuffer_error;
    }

    msgpack_pack_str_with_body(&mp_pck, "start_time", strlen("start_time"));
    //msgpack_pack_double(&mp_pck, flb_time_to_double(tm_start));
    flb_time_append_to_msgpack(tm_start, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, "end_time", strlen("end_time"));
    //msgpack_pack_double(&mp_pck, flb_time_to_double(tm_end));
    flb_time_append_to_msgpack(tm_end, &mp_pck, FLB_TIME_ETFMT_INT);

    msgpack_pack_str_with_body(&mp_pck, "trace_id", strlen("trace_id"));
    msgpack_pack_str_with_body(&mp_pck, tracer->trace_id, strlen(tracer->trace_id));


    msgpack_pack_str_with_body(&mp_pck, "plugin_instance", strlen("plugin_instance"));
    rc = msgpack_pack_str_with_body(&mp_pck, filter->name, strlen(filter->name));
    if (rc == -1) {
        goto sbuffer_error;
    }

    if (filter->alias != NULL) {
        msgpack_pack_str_with_body(&mp_pck, "plugin_alias", strlen("plugin_alias"));
        msgpack_pack_str_with_body(&mp_pck, filter->alias, strlen(filter->alias));
    }

    msgpack_pack_str_with_body(&mp_pck, "records", strlen("records"));

    msgpack_unpacked_init(&result);

    if (buf_size > 0) {
        do {
            rc = msgpack_unpack_next(&result, buf, buf_size, &off);
            if (rc != MSGPACK_UNPACK_SUCCESS) {
                flb_error("unable to unpack record");
                goto unpack_error;
            }
            records++;
        } while (rc == MSGPACK_UNPACK_SUCCESS && off < buf_size);

        msgpack_pack_array(&mp_pck, records);
        off = 0;
        do {
            rc = msgpack_unpack_next(&result, buf, buf_size, &off);
            if (rc != MSGPACK_UNPACK_SUCCESS) {
                flb_error("unable to unpack record");
                goto unpack_error;
            }
            flb_time_pop_from_msgpack(&tm, &result, &record);

            msgpack_pack_map(&mp_pck, 2);
            msgpack_pack_str_with_body(&mp_pck, "timestamp", strlen("timestamp"));
            flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
            msgpack_pack_str_with_body(&mp_pck, "record", strlen("record"));
            msgpack_pack_object(&mp_pck, *record);

        } while (rc == MSGPACK_UNPACK_SUCCESS && off < buf_size);
    }

    flb_input_log_append(tracer->ctxt->input,
                         tag, flb_sds_len(tag),
                         mp_sbuf.data, mp_sbuf.size);
    // in_emitter_add_record(tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size,
    //                      tracer->ctxt->input);

    rc = 0;

unpack_error:
    msgpack_unpacked_destroy(&result);
sbuffer_error:
    msgpack_sbuffer_destroy(&mp_sbuf);
tracer_error:
    flb_sds_destroy(tag);
    return rc;
}

int flb_chunk_trace_output(struct flb_chunk_trace *trace, struct flb_output_instance *output, int ret)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    struct flb_time tm;
    struct flb_time tm_end;
    int rc = -1;
    flb_sds_t tag = flb_sds_create("trace");


    /* initiailize start time */
    flb_time_get(&tm);
    flb_time_get(&tm_end);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    if (output->alias != NULL) {
        msgpack_pack_map(&mp_pck, 7);
    }
    else {
        msgpack_pack_map(&mp_pck, 6);
    }

    msgpack_pack_str_with_body(&mp_pck, "type", 4);
    msgpack_pack_int(&mp_pck, FLB_CHUNK_TRACE_TYPE_OUTPUT);

    msgpack_pack_str_with_body(&mp_pck, "trace_id", strlen("trace_id"));
    msgpack_pack_str_with_body(&mp_pck, trace->trace_id, strlen(trace->trace_id));

    msgpack_pack_str_with_body(&mp_pck, "plugin_instance", strlen("plugin_instance"));
    msgpack_pack_str_with_body(&mp_pck, output->name, strlen(output->name));

    if (output->alias != NULL) {
        msgpack_pack_str_with_body(&mp_pck, "plugin_alias", strlen("plugin_alias"));
        msgpack_pack_str_with_body(&mp_pck, output->alias, strlen(output->alias));
    }

    msgpack_pack_str_with_body(&mp_pck, "return", strlen("return"));
    msgpack_pack_int(&mp_pck, ret);

    msgpack_pack_str_with_body(&mp_pck, "start_time", strlen("start_time"));
    flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, "end_time", strlen("end_time"));
    flb_time_append_to_msgpack(&tm_end, &mp_pck, FLB_TIME_ETFMT_INT);
    flb_input_log_append(trace->ctxt->input,
                         tag, flb_sds_len(tag),
                         mp_sbuf.data, mp_sbuf.size);
    flb_sds_destroy(tag);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
    return rc;
}
