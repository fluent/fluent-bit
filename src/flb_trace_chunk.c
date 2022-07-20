#include <fcntl.h>

#include <msgpack.h>
#include <chunkio/chunkio.h>

#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_trace_chunk.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_kv.h>


/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in);

struct flb_trace_chunk *flb_trace_chunk_new(struct flb_input_chunk *chunk)
{
    struct flb_trace_chunk *trace;
    struct flb_input_instance *f_ins = (struct flb_input_instance *)chunk->in;

    trace = flb_calloc(1, sizeof(struct flb_trace_chunk));
    if (trace == NULL) {
        return NULL;
    }

    trace->ctxt = f_ins->trace_ctxt;
    trace->ctxt->chunks++;

    trace->ic = chunk;
    trace->trace_id = flb_sds_create("");
    flb_sds_printf(&trace->trace_id, "%s%d", trace->ctxt->trace_prefix,
                  trace->ctxt->trace_count++);
    return trace;
}

void flb_trace_chunk_destroy(struct flb_trace_chunk *trace)
{
    trace->ctxt->chunks--;
    if (trace->ctxt->chunks == 0 && trace->ctxt->to_destroy) {
        flb_trace_chunk_context_destroy(trace->ctxt);
    }
    flb_sds_destroy(trace->trace_id);
    flb_free(trace);
}

static struct flb_output_instance *find_calyptia_output_instance(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_output_instance *output;

    mk_list_foreach(head, &config->outputs) {
        output = mk_list_entry(head, struct flb_output_instance, _head);
        if (strcmp(output->p->name, "calyptia") == 0) {
            return output;
        }
    }
    return NULL;
}

struct flb_trace_chunk_context *flb_trace_chunk_context_new(struct flb_config *config, const char *output_name, const char *trace_prefix, struct mk_list *props)
{
    struct flb_input_instance *input;
    struct flb_output_instance *output;
    struct flb_output_instance *calyptia;
    struct flb_trace_chunk_context *ctx;
    struct mk_list *head;
    struct flb_kv *prop;
    struct cio_options opts = {0};
    int ret;

    if (config->enable_trace == FLB_FALSE) {
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct flb_trace_chunk_context));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->flb = flb_create();
    if (ctx->flb == NULL) {
        goto error_ctxt;
    }

    flb_service_set(ctx->flb, "flush", "1", "grace", "1", NULL);

    input = (void *)flb_input_new(ctx->flb->config, "emitter", NULL, FLB_FALSE);
    if (input == NULL) {
        flb_error("could not load trace emitter");
        goto error_flb;
    }
    input->event_type = FLB_EVENT_TYPE_LOG | FLB_EVENT_TYPE_HAS_TRACE;

    ctx->cio = cio_create(NULL);
    if (ctx->cio == NULL) {
    	flb_error("unable to create cio context");
    	return NULL;
    }
    flb_storage_input_create(ctx->cio, input);

    ret = flb_input_set_property(input, "alias", "trace-emitter");
    if (ret != 0) {
        flb_error("unable to set alias for trace emitter");
        goto error_input;
    }

    output = flb_output_new(ctx->flb->config, output_name, NULL, 1);
    if (output == NULL) {
        flb_error("could not create trace output");
        goto error_input;
    }
    
    if (strcmp(output_name, "calyptia") == 0) {
        calyptia = find_calyptia_output_instance(config);
        if (calyptia == NULL) {
            flb_error("unable to find calyptia output instance");
            goto error_output;
        }
        mk_list_foreach(head, &calyptia->properties) {
            prop = mk_list_entry(head, struct flb_kv, _head);
            flb_output_set_property(output, prop->key, prop->val);
        }        
    } else if (props != NULL) {
        mk_list_foreach(head, props) {
            prop = mk_list_entry(head, struct flb_kv, _head);
            flb_output_set_property(output, prop->key, prop->val);
        }
    }

    ret = flb_router_connect_direct(input, output);
    if (ret != 0) {
        flb_error("unable to route traces");
        goto error_output;
    }

    flb_router_connect(input, output);

    ctx->output = (void *)output;
    ctx->input = (void *)input;
    ctx->trace_prefix = flb_sds_create(trace_prefix);

    flb_start(ctx->flb);
    
    return ctx;

error_output:
    flb_output_instance_destroy(output);
error_input:
    if (ctx->cio) {
        cio_destroy(ctx->cio);
    }
    flb_input_instance_destroy(input);
error_flb:
    flb_destroy(ctx->flb);
error_ctxt:
    flb_free(ctx);
    return NULL;
}

int flb_trace_chunk_context_set_limit(struct flb_trace_chunk_context *ctxt, int limit_type, int limit_arg)
{
    struct flb_time tm;


    switch(limit_type) {
    case FLB_TRACE_CHUNK_LIMIT_TIME:
        flb_time_get(&tm);
        ctxt->limit.type = FLB_TRACE_CHUNK_LIMIT_TIME;
        ctxt->limit.seconds_started = tm.tm.tv_sec;
        ctxt->limit.seconds = limit_arg;
        return 0;
    case FLB_TRACE_CHUNK_LIMIT_COUNT:
        ctxt->limit.type = FLB_TRACE_CHUNK_LIMIT_COUNT;
        ctxt->limit.count = limit_arg;
        return 0;
    default:
        return -1;
    }
}

int flb_trace_chunk_context_hit_limit(struct flb_trace_chunk_context *ctxt)
{
    struct flb_time tm;


    switch(ctxt->limit.type) {
    case FLB_TRACE_CHUNK_LIMIT_TIME:
        flb_time_get(&tm);
        if ((tm.tm.tv_sec - ctxt->limit.seconds_started) > ctxt->limit.seconds) {
            return FLB_TRUE;
        }
        return FLB_FALSE;
    case FLB_TRACE_CHUNK_LIMIT_COUNT:
        if (ctxt->limit.count <= ctxt->trace_count) {
            return FLB_TRUE;
        }
        return FLB_FALSE;
    }
    return FLB_FALSE;
}

void flb_trace_chunk_context_destroy(struct flb_trace_chunk_context *ctxt)
{
    if (ctxt->chunks > 0) {
        ctxt->to_destroy = 1;
        return;
    }
    flb_stop(ctxt->flb);
    flb_destroy(ctxt->flb);
    cio_destroy(ctxt->cio);
    flb_free(ctxt);
}

int flb_trace_chunk_input(struct flb_trace_chunk *trace)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *record;
    char *buf;
    size_t buf_size;
    struct flb_time tm;
    struct flb_time tm_end;
    struct flb_input_instance *input = (struct flb_input_instance *)trace->ic->in;
    int rc = -1;
    size_t off = 0;
    flb_sds_t tag = flb_sds_create("trace");
    int records = 0;


    // initiailize start time
    flb_time_get(&tm);
    flb_time_get(&tm_end);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    cio_chunk_get_content(trace->ic->chunk, &buf, &buf_size);
    
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, 6);

    msgpack_pack_str_with_body(&mp_pck, "type", 4);
    msgpack_pack_int(&mp_pck, FLB_TRACE_CHUNK_TYPE_INPUT);

    msgpack_pack_str_with_body(&mp_pck, "trace_id", strlen("trace_id"));
    msgpack_pack_str_with_body(&mp_pck, trace->trace_id, strlen(trace->trace_id));

    msgpack_pack_str_with_body(&mp_pck, "input_instance", strlen("input_instance"));
    msgpack_pack_str_with_body(&mp_pck, input->name, strlen(input->name));

    msgpack_pack_str_with_body(&mp_pck, "records", strlen("records"));

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

    msgpack_pack_str_with_body(&mp_pck, "start_time", strlen("start_time"));
    flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, "end_time", strlen("end_time"));
    flb_time_append_to_msgpack(&tm_end, &mp_pck, FLB_TIME_ETFMT_INT);
    in_emitter_add_record(tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size,
                          trace->ctxt->input);
sbuffer_error:
    flb_sds_destroy(tag);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
    return rc;
}

int flb_trace_chunk_pre_output(struct flb_trace_chunk *trace)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *record;
    char *buf;
    size_t buf_size;
    struct flb_time tm;
    struct flb_time tm_end;
    struct flb_input_instance *input = (struct flb_input_instance *)trace->ic->in;
    int rc = -1;
    size_t off = 0;
    flb_sds_t tag = flb_sds_create("trace");
    int records = 0;


    // initiailize start time
    flb_time_get(&tm);
    flb_time_get(&tm_end);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    cio_chunk_get_content(trace->ic->chunk, &buf, &buf_size);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, 6);

    msgpack_pack_str_with_body(&mp_pck, "type", 4);
    msgpack_pack_int(&mp_pck, FLB_TRACE_CHUNK_TYPE_PRE_OUTPUT);

    msgpack_pack_str_with_body(&mp_pck, "trace_id", strlen("trace_id"));
    msgpack_pack_str_with_body(&mp_pck, trace->trace_id, strlen(trace->trace_id));

    msgpack_pack_str_with_body(&mp_pck, "input_instance", strlen("input_instance"));
    msgpack_pack_str_with_body(&mp_pck, input->name, strlen(input->name));

    msgpack_pack_str_with_body(&mp_pck, "records", strlen("records"));

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

    msgpack_pack_str_with_body(&mp_pck, "start_time", strlen("start_time"));
    flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, "end_time", strlen("end_time"));
    flb_time_append_to_msgpack(&tm_end, &mp_pck, FLB_TIME_ETFMT_INT);
    in_emitter_add_record(tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size,
                          trace->ctxt->input);
sbuffer_error:
    flb_sds_destroy(tag);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
    return rc;
}

int flb_trace_chunk_filter(struct flb_trace_chunk *tracer, void *pfilter, struct flb_time *tm_start, struct flb_time *tm_end, char *buf, size_t buf_size)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object *record;
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
    msgpack_pack_map(&mp_pck, 6);

    msgpack_pack_str_with_body(&mp_pck, "type", strlen("type"));
    rc = msgpack_pack_int(&mp_pck, FLB_TRACE_CHUNK_TYPE_FILTER);
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

    
    msgpack_pack_str_with_body(&mp_pck, "filter_instance", strlen("filter_instance"));
    rc = msgpack_pack_str_with_body(&mp_pck, filter->name, strlen(filter->name));
    if (rc == -1) {
        goto sbuffer_error;
    }
    
    msgpack_pack_str_with_body(&mp_pck, "records", strlen("records"));

    msgpack_unpacked_init(&result);
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

    in_emitter_add_record(tag, flb_sds_len(tag), mp_sbuf.data, mp_sbuf.size,
                          tracer->ctxt->input);
    
    rc = 0;

unpack_error:
    msgpack_unpacked_destroy(&result);
sbuffer_error:
    msgpack_sbuffer_destroy(&mp_sbuf);
tracer_error:
    flb_sds_destroy(tag);
    return rc;
}
