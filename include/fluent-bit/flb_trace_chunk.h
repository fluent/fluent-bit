#pragma once

#include <fluent-bit/flb_time.h>

#define FLB_TRACE_CHUNK_TYPE_INPUT 1
#define FLB_TRACE_CHUNK_TYPE_FILTER 2
#define FLB_TRACE_CHUNK_TYPE_OUTPUT 3

struct flb_trace_chunk_input_record {
	struct flb_time t;
	void *input;
	char *buf;
	size_t buf_size;
};

struct flb_trace_chunk_filter_record {
	struct flb_time t;
	int trace_version;
	void *filter;
	char *buf;
	size_t buf_size;
};

struct flb_trace_chunk {
	struct flb_input_chunk *ic;
	int trace_id;
	int tracer_versions;
	struct flb_trace_chunk_input_record input;
	int num_filters;
	struct flb_trace_chunk_filter_record *filters;
};

struct flb_trace_chunk *flb_trace_chunk_new(struct flb_input_chunk *chunk);
int flb_trace_chunk_input(struct flb_trace_chunk *trace, void *pinput);
int flb_trace_chunk_filter(struct flb_trace_chunk *trace, void *pfilter);
int flb_trace_chunk_flush(struct flb_trace_chunk *trace, int offset);
void flb_trace_chunk_free(struct flb_trace_chunk *trace);
