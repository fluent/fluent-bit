#pragma once

#include <fluent-bit/flb_time.h>

#define FLB_CHUNK_TRACE_TYPE_INPUT 1
#define FLB_CHUNK_TRACE_TYPE_FILTER 2
#define FLB_CHUNK_TRACE_TYPE_OUTPUT 3

struct flb_chunk_trace_input_record {
	struct flb_time t;
	void *input;
	char *buf;
	size_t buf_size;
};

struct flb_chunk_trace_filter_record {
	struct flb_time t;
	int trace_version;
	void *filter;
	char *buf;
	size_t buf_size;
};

struct flb_chunk_trace {
	struct flb_input_chunk *ic;
	int trace_id;
	int tracer_versions;
	struct flb_chunk_trace_input_record input;
	int num_filters;
	struct flb_chunk_trace_filter_record *filters;
};

struct flb_chunk_trace *flb_chunk_trace_new(struct flb_input_chunk *chunk);
int flb_chunk_trace_input(struct flb_chunk_trace *trace, void *pinput);
int flb_chunk_trace_filter(struct flb_chunk_trace *trace, void *pfilter);
int flb_chunk_trace_flush(struct flb_chunk_trace *trace, int offset);
void flb_chunk_trace_free(struct flb_chunk_trace *trace);
