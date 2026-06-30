/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_AWS_COMPRESS
#define FLB_AWS_COMPRESS

#include <sys/types.h>
#define FLB_AWS_COMPRESS_NONE    0
#define FLB_AWS_COMPRESS_GZIP    1
#define FLB_AWS_COMPRESS_ZSTD    4
#define FLB_AWS_COMPRESS_SNAPPY  5

/*
 * Get compression type from compression keyword. The return value is used to identify
 * what compression option to utilize.
 *
 * Returns int compression type id - FLB_AWS_COMPRESS_<compression-type>
 */
int flb_aws_compression_get_type(const char *compression_keyword);

/*
 * Compress in_data and write result to newly allocated out_data buf
 * Client is responsable for freeing out_data.
 *
 * Returns -1 on error
 * Returns 0 on success
 */
int flb_aws_compression_compress(int compression_type, void *in_data, size_t in_len,
                                void **out_data, size_t *out_len);

/*
 * Truncate and compress in_data and convert to b64
 * If b64 output data is larger than max_out_len, the input is truncated with a
 * [Truncated...] suffix appended to the end, and recompressed. The result is written to a
 * newly allocated out_data buf.
 * Client is responsable for freeing out_data.
 *
 * out_len and max_out_len do not count the null character as a part of out_data's length,
 * though the null character may be included at the end of out_data.
 *
 * Returns -1 on error
 * Returns 0 on success
 */
int flb_aws_compression_b64_truncate_compress(int compression_type, size_t max_out_len,
                                             void *in_data, size_t in_len,
                                             void **out_data, size_t *out_len);

/*
 * Columnar output formats for out_s3_compress_columnar(). Compression is
 * applied on top of the format via a generic FLB_AWS_COMPRESS_* codec.
 */
#define FLB_AWS_COMPRESS_FORMAT_ARROW    0
#define FLB_AWS_COMPRESS_FORMAT_PARQUET  1

/*
 * Convert JSON data to a columnar format (Apache Arrow/Feather or Apache
 * Parquet) selected by `columnar_format` (FLB_AWS_COMPRESS_FORMAT_*),
 * applying `compression_type` (a generic FLB_AWS_COMPRESS_* codec) on top of
 * the format:
 *   - Parquet supports NONE, SNAPPY, GZIP and ZSTD (page-level codec).
 *   - Arrow/Feather supports NONE and ZSTD only.
 *
 * Returns 0 on success, -1 on failure.
 */
int out_s3_compress_columnar(int columnar_format, void *json, size_t size,
                             void **out_buf, size_t *out_size,
                             int compression_type);

#endif
