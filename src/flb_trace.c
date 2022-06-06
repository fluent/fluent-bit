#include <fcntl.h>

#include <msgpack.h>

#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_trace.h>


static int record_resize(msgpack_packer *mp_pck, msgpack_sbuffer *mp_sbuf, void *buf, size_t buf_size, int add_size)
{
	msgpack_unpacked result;
	int rc = -1;
	int ret;
	size_t off = 0;
	int i;
	

	msgpack_unpacked_init(&result);
	ret = msgpack_unpack_next(&result, buf, buf_size, &off);
	if (ret != MSGPACK_UNPACK_SUCCESS) {
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

int flb_trace_input_write(struct flb_input_chunk *ic, int trace_id)
{
	msgpack_sbuffer mp_sbuf;
	msgpack_packer mp_pck;
	void *buf;
	size_t buf_size;
	char trace_id_buf[256];
	int slen;
	int rc = -1;
	
	cio_chunk_get_content(ic->chunk, &buf, &buf_size);

	msgpack_sbuffer_init(&mp_sbuf);
	msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

	slen = snprintf(trace_id_buf, sizeof(trace_id_buf)-1, "%s.%d", 
	         ic->in->name, trace_id);
	if (slen <= 0) {
		goto sbuffer_error;
	}

	record_resize(&mp_pck, &mp_sbuf, buf, buf_size, 2);
	msgpack_pack_int(&mp_pck, FLB_TRACE_TYPE_INPUT);
	msgpack_pack_str_with_body(&mp_pck, trace_id_buf, slen);
	
	rc = flb_input_chunk_write_at(ic, 0, mp_sbuf.data, mp_sbuf.size);
sbuffer_error:
	msgpack_sbuffer_destroy(&mp_sbuf);
	return rc;
}

int flb_trace_filter_write(void *pfilter, void *pic)
{
	struct flb_filter_instance *filter = (struct flb_filter_instance *)pfilter;
	struct flb_input_chunk *ic = (struct flb_input_chunk *)pic;
	msgpack_packer mp_pck;
	msgpack_sbuffer mp_sbuf;
	void *buf;
	size_t buf_size;
	int rc = -1;

	msgpack_sbuffer_init(&mp_sbuf);
	msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
	
	cio_chunk_get_content(&buf, &buf_size);
	record_resize(&mp_pck, &mp_sbuf, buf, buf_size, 2);

	rc = msgpack_pack_int(&mp_pck, FLB_TRACE_TYPE_FILTER);
	if (rc == -1) {
		goto sbuffer_error;
	}

	rc = msgpack_pack_array(&mp_pck, 3);
	flb_pack_time_now(mp_pck);
	rc = msgpack_pack_str_with_body(&mp_pck, filter->name, strlen(filter->name));
	if (rc == -1) {
		goto sbuffer_error;
	}
	rc = msgpack_pack_int(&mp_pck, ic->trace_version++);
	if (rc == -1) {
		goto sbuffer_error;
	}

	rc = flb_input_chunk_write_at(ic, 0, mp_sbuf.data, mp_sbuf.size);
sbuffer_error:
	msgpack_sbuffer_destroy(&mp_sbuf);
	return rc;
}
