/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_AWS_AGGREGATION_H
#define FLB_AWS_AGGREGATION_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>

/* Aggregation buffer structure */
struct flb_aws_agg_buffer {
    char *agg_buf;           /* aggregated records buffer */
    size_t agg_buf_size;     /* total size of aggregation buffer */
    size_t agg_buf_offset;   /* current offset in aggregation buffer */
};

/* Initialize aggregation buffer
 * Returns:
 *   0 = success
 *  -1 = error
 */
int flb_aws_aggregation_init(struct flb_aws_agg_buffer *buf, size_t max_record_size);

/* Destroy aggregation buffer */
void flb_aws_aggregation_destroy(struct flb_aws_agg_buffer *buf);

/* Try to add event data to aggregation buffer
 * Returns:
 *   0 = success, event added to aggregation buffer
 *   1 = buffer full, caller should finalize and retry
 */
int flb_aws_aggregation_add(struct flb_aws_agg_buffer *buf,
                            const char *data, size_t data_len,
                            size_t max_record_size);

/* Finalize aggregated record
 * Returns:
 *   0 = success
 *  -1 = error (no data to finalize)
 *
 * Output is written to buf->agg_buf and the size is returned via out_size parameter
 */
int flb_aws_aggregation_finalize(struct flb_aws_agg_buffer *buf,
                                 int add_final_newline,
                                 size_t *out_size);

/* Reset aggregation buffer for reuse */
void flb_aws_aggregation_reset(struct flb_aws_agg_buffer *buf);

/* Process event with simple aggregation
 * Converts msgpack to JSON, optionally adds log_key and time_key,
 * then adds to aggregation buffer
 *
 * Returns:
 *  -1 = failure, record not added
 *   0 = success, record added
 *   1 = buffer full, caller should finalize and retry
 *   2 = record could not be processed, discard it
 */
int flb_aws_aggregation_process_event(struct flb_aws_agg_buffer *agg_buf,
                                      char *tmp_buf,
                                      size_t tmp_buf_size,
                                      size_t *tmp_buf_offset,
                                      const msgpack_object *obj,
                                      struct flb_time *tms,
                                      struct flb_config *config,
                                      struct flb_output_instance *ins,
                                      const char *stream_name,
                                      const char *log_key,
                                      const char *time_key,
                                      const char *time_key_format,
                                      size_t max_event_size);

#endif
