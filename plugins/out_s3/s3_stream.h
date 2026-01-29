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

#ifndef FLB_OUT_S3_STREAM_H
#define FLB_OUT_S3_STREAM_H

#include "s3.h"
#include <fluent-bit/flb_sds.h>
#include <msgpack.h>
#include <stdio.h>
#include <sys/types.h>  /* for off_t */

/* Record processor callback function type */
typedef int (*record_processor_fn)(
    struct flb_s3 *ctx,
    const msgpack_object *record,
    FILE *output_file,
    void *processor_ctx
);

/* Stream processor context */
struct stream_processor_context {
    record_processor_fn processor;
    void *user_data;
    size_t records_processed;
    size_t bytes_written;
};

/**
 * Compress file or file segment using streaming approach
 *
 * Supports compression starting from any offset for memory-efficient
 * processing of large files.
 *
 * @param ctx          S3 context
 * @param input_path   Input file path
 * @param output_path  Output file path
 * @param offset_start Start offset (0 for beginning)
 * @param offset_end   End offset (-1 for EOF)
 * @return 0 on success, -1 on failure
 */
int stream_compress_file(struct flb_s3 *ctx,
                        const char *input_path,
                        const char *output_path,
                        off_t offset_start,
                        off_t offset_end);

/**
 * Unified msgpack streaming processor
 *
 * Provides a unified framework for processing msgpack data with
 * format-specific callbacks.
 *
 * @param ctx             S3 context
 * @param input_path      Input msgpack file path
 * @param input_size      Input file size
 * @param output_suffix   Output file suffix (e.g., ".json", ".txt")
 * @param processor       Format-specific processor callback
 * @param processor_ctx   User data for processor
 * @param out_buf         Output buffer (FILE: marker for temp file)
 * @param out_size        Output size
 * @return 0 on success, -1 on failure
 */
int stream_process_msgpack_file(
    struct flb_s3 *ctx,
    const char *input_path,
    size_t input_size,
    const char *output_suffix,
    record_processor_fn processor,
    void *processor_ctx,
    flb_sds_t *out_buf,
    size_t *out_size);

/**
 * JSON record processor
 *
 * Converts msgpack records to JSON line format.
 */
int stream_json_processor(
    struct flb_s3 *ctx,
    const msgpack_object *record,
    FILE *output_file,
    void *proc_ctx_ptr);

/**
 * log_key record processor
 *
 * Extracts specified field value from records.
 */
int stream_log_key_processor(
    struct flb_s3 *ctx,
    const msgpack_object *record,
    FILE *output_file,
    void *proc_ctx_ptr);

#endif /* FLB_OUT_S3_STREAM_H */
