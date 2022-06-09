#include <fcntl.h>

#include <msgpack.h>
#include <chunkio/chunkio.h>

#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_trace_chunk.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_base64.h>


static int record_resize(msgpack_packer *mp_pck, msgpack_sbuffer *mp_sbuf, void *buf, size_t buf_size, int add_size)
{
    msgpack_unpacked result;
    int rc = -1;
    int ret;
    size_t off = 0;
    int i;
    

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS && ret != MSGPACK_UNPACK_CONTINUE) {
        goto unpack_error;
    }
    
    msgpack_pack_array(mp_pck, result.data.via.array.size + add_size);
    for (i = 0; i < result.data.via.array.size; i++) {
        msgpack_pack_object(mp_pck, result.data.via.array.ptr[i]);
    }

    rc = 0;
unpack_error:
    msgpack_unpacked_destroy(&result);
    return rc;
}

struct flb_trace_chunk *flb_trace_chunk_new(struct flb_input_chunk *chunk)
{
    struct flb_trace_chunk *trace;
    struct flb_input_instance *f_ins = (struct flb_input_instance *)chunk->in;

    trace = flb_calloc(1, sizeof(struct flb_trace_chunk));
    if (trace == NULL) {
        return NULL;
    }

    trace->ic = chunk;
    trace->trace_id = f_ins->chunk_trace_count++;

    chunk->chunk_trace = (void *)trace;
    return trace;
}

void flb_trace_chunk_free(struct flb_trace_chunk *trace)
{
    if (trace->filters) {
        flb_free(trace->filters);
    }
    flb_free(trace);
}

int flb_trace_chunk_input(struct flb_trace_chunk *tracer, void *pinput)
{
    if (tracer == NULL) {
        return -1;
    }

    flb_time_get(&tracer->input.t);
    tracer->input.input = pinput;
    cio_chunk_get_content(tracer->ic->chunk, 
                          &tracer->input.buf,
                  &tracer->input.buf_size);
    return 0;
}

int flb_trace_chunk_filter(struct flb_trace_chunk *tracer, void *pfilter)
{
    if (tracer == NULL) {
        return -1;
    }

    tracer->filters = flb_realloc(tracer->filters,
                      sizeof(struct flb_trace_chunk_filter_record) * (tracer->num_filters+1));
    flb_time_get(&tracer->filters[tracer->num_filters].t);
    tracer->filters[tracer->num_filters].filter =  pfilter;
    cio_chunk_get_content(tracer->ic->chunk,
                          &tracer->filters[tracer->num_filters].buf,
                  &tracer->filters[tracer->num_filters].buf_size);
    tracer->filters[tracer->num_filters].trace_version = tracer->tracer_versions++;
    tracer->num_filters++;
    return 0;
}

int flb_trace_chunk_flush(struct flb_trace_chunk *tracer, int offset)
{
    if (tracer == NULL) {
        return -1;
    }

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_input_instance *input;
    struct flb_filter_instance *filter;
    char *buf;
    size_t buf_size;
    int rc = -1;
    int slen;
    int i;
    unsigned char b64enc[102400];
    size_t bc64enclen;
    char trace_id_buf[256];


    input = (struct flb_input_instance *)tracer->input.input;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    cio_chunk_get_content(tracer->ic->chunk, &buf, &buf_size);
    record_resize(&mp_pck, &mp_sbuf, buf, buf_size, 5 + (tracer->num_filters * 6));

    slen = snprintf(trace_id_buf, sizeof(trace_id_buf)-1, "%s.%d", 
           input->name, tracer->trace_id);
    if (slen <= 0) {
        goto sbuffer_error;
    }

    msgpack_pack_int(&mp_pck, FLB_TRACE_CHUNK_TYPE_INPUT);
    flb_time_append_to_msgpack(&tracer->input.t, &mp_pck, FLB_TIME_ETFMT_INT);
    msgpack_pack_str_with_body(&mp_pck, trace_id_buf, slen);
    msgpack_pack_str_with_body(&mp_pck, input->name, strlen(input->name));

    flb_base64_encode(b64enc, sizeof(b64enc)-1, &bc64enclen,
                    (unsigned char *)tracer->input.buf,
                    tracer->input.buf_size);
    msgpack_pack_str_with_body(&mp_pck, b64enc, bc64enclen);

    for (i = 0; i < tracer->num_filters; i++) {
        filter = (struct flb_filter_instance *)tracer->filters[i].filter;

        rc = msgpack_pack_int(&mp_pck, FLB_TRACE_CHUNK_TYPE_FILTER);
        if (rc == -1) {
            goto sbuffer_error;
        }

        flb_time_append_to_msgpack(&tracer->filters[i].t, &mp_pck, FLB_TIME_ETFMT_INT);
        msgpack_pack_str_with_body(&mp_pck, trace_id_buf, slen);
        rc = msgpack_pack_str_with_body(&mp_pck, filter->name, strlen(filter->name));
        if (rc == -1) {
            goto sbuffer_error;
        }
        rc = msgpack_pack_int(&mp_pck, tracer->filters[i].trace_version);
        if (rc == -1) {
            goto sbuffer_error;
        }

        flb_base64_encode(b64enc, sizeof(b64enc)-1, &bc64enclen,
                    (unsigned char *)tracer->filters[i].buf, 
                    tracer->filters[i].buf_size);
        msgpack_pack_str_with_body(&mp_pck, b64enc, bc64enclen);
    }

    rc = mp_sbuf.size;
    flb_input_chunk_write_at(tracer->ic, offset, mp_sbuf.data, mp_sbuf.size);
sbuffer_error:
    msgpack_sbuffer_destroy(&mp_sbuf);
    return rc;
}
