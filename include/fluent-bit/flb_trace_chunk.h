#pragma once

#include <fluent-bit/flb_time.h>

// A record has been received from input
#define FLB_TRACE_CHUNK_TYPE_INPUT      1
// A record has been filtered
#define FLB_TRACE_CHUNK_TYPE_FILTER     2
// A trace with the final record before output
#define FLB_TRACE_CHUNK_TYPE_PRE_OUTPUT 3
// A record has been output
#define FLB_TRACE_CHUNK_TYPE_OUTPUT     4

#define FLB_TRACE_CHUNK_LIMIT_TIME    1
#define FLB_TRACE_CHUNK_LIMIT_COUNT   2

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

struct flb_trace_chunk_limit {
	// set to one of:
	//   FLB_TRACE_CHUNK_LIMIT_TIME
	//   FLB_TRACE_CHUNK_LIMIT_COUNT
	int type;

	// limit is in seconds
	int seconds;
	// unix timestamp when time limit started
	int seconds_started;

	// limit is a count
	int count;
};

struct flb_trace_chunk_context {
	/* avoid cyclical include ... */
	void *input;
	void *output;
	int trace_count;
	struct flb_trace_chunk_limit limit;
	flb_sds_t trace_prefix;
	int to_destroy;
	int chunks;
};

struct flb_trace_chunk {
	struct flb_input_chunk *ic;
	struct flb_trace_chunk_context *ctxt;
	flb_sds_t trace_id;
	int tracer_versions;
};

struct flb_trace_chunk_context *flb_trace_chunk_context_new(struct flb_config *config, const char *output_name, const char *trace_prefix, struct mk_list *props);
void flb_trace_chunk_context_destroy(struct flb_trace_chunk_context *ctxt);
struct flb_trace_chunk *flb_trace_chunk_new(struct flb_input_chunk *chunk);
void flb_trace_chunk_destroy(struct flb_trace_chunk *);
int flb_trace_chunk_input(struct flb_trace_chunk *trace, char *buf, int buf_size);
int flb_trace_chunk_pre_output(struct flb_trace_chunk *trace, char *buf, int buf_size);
int flb_trace_chunk_filter(struct flb_trace_chunk *trace, void *pfilter, char *buf, int buf_size);
void flb_trace_chunk_free(struct flb_trace_chunk *trace);
int flb_trace_chunk_context_set_limit(struct flb_trace_chunk_context *ctxt, int, int);
int flb_trace_chunk_context_hit_limit(struct flb_trace_chunk_context *ctxt);
