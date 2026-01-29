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

/*
 * Compression algorithms (true compression)
 * Valid values: none, gzip, snappy, zstd
 *
 * Note: Snappy compression uses the Snappy framing format (Google Snappy framing_format.txt)
 * which supports streaming/concatenation. This is handled internally via flb_snappy_compress_framed_data().
 */
#define FLB_AWS_COMPRESS_NONE    0
#define FLB_AWS_COMPRESS_GZIP    1
#define FLB_AWS_COMPRESS_SNAPPY  2
#define FLB_AWS_COMPRESS_ZSTD    3

/*
 * File format conversion (NOT compression algorithms)
 *
 * DEPRECATED: FLB_AWS_COMPRESS_ARROW (4)
 *   - Arrow is not a proper file format for S3
 *   - This value is kept only for backward compatibility to avoid compilation errors
 *   - DO NOT USE in new code
 *
 * Valid file format: PARQUET (5)
 *   - Use format=parquet instead of compression=parquet (deprecated usage)
 *   - Supported S3 output formats: json (FLB_S3_FORMAT_JSON), parquet (FLB_S3_FORMAT_PARQUET)
 */
#define FLB_AWS_COMPRESS_ARROW   4  /* DEPRECATED - Do not use */
#define FLB_AWS_COMPRESS_PARQUET 5  /* Use format=parquet instead */

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

#endif
