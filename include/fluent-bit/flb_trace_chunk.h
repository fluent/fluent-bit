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

struct flb_trace_chunk_context {
	/* avoid cyclical include ... */
	void *input;
	void *output;
	int trace_count;
	flb_sds_t trace_prefix;
};

struct flb_trace_chunk {
	struct flb_input_chunk *ic;
	struct flb_trace_chunk_context *ctxt;
	flb_sds_t trace_id;
	int tracer_versions;
};

struct flb_trace_chunk_context *flb_trace_chunk_context_new(struct flb_config *config, const char *output_name, const char *trace_prefix, struct mk_list *props);
struct flb_trace_chunk *flb_trace_chunk_new(struct flb_input_chunk *chunk);
int flb_trace_chunk_input(struct flb_trace_chunk *trace, char *buf, int buf_size);
int flb_trace_chunk_filter(struct flb_trace_chunk *trace, void *pfilter, char *buf, int buf_size);
void flb_trace_chunk_free(struct flb_trace_chunk *trace);
