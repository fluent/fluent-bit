#pragma once

#define FLB_TRACE_TYPE_INPUT 1
#define FLB_TRACE_TYPE_FILTER 2
#define FLB_TRACE_TYPE_OUTPUT 3

int flb_trace_input_write(struct flb_input_chunk *ic, int trace_id);
int flb_trace_filter_write(void *pfilter, void *input_chunk);
