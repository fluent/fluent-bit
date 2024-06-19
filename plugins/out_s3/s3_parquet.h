/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_OUT_S3_PARQUET
#define FLB_OUT_S3_PARQUET

#include <fluent-bit/flb_output_plugin.h>

#define DEFAULT_PARQUET_COMPRESSION_FORMAT         "snappy"
#define DEFAULT_PARQUET_COMPRESSION_FORMAT_UPCASES "SNAPPY"
#define DEFAULT_PARQUET_RECORD_TYPE                "jsonl"
#define DEFAULT_PARQUET_SCHEMA_TYPE                "avro"
#define DEFAULT_PARQUET_COMMAND                    "columnify"
#if defined(FLB_SYSTEM_WINDOWS)
#define DEFAULT_PARQUET_COMMAND_CHECK              "where columnify"
#else
#define DEFAULT_PARQUET_COMMAND_CHECK              "columnify -h > /dev/null  2>&1"
#endif

#ifdef __ANDROID__
#define DEFAULT_PARQUET_PROCESS_DIR "/data/local/tmp/parquet/s3"
#else
#if defined(FLB_SYSTEM_WINDOWS)
/* The prefix of process dir will be obtained by GetTempPathA */
#define DEFAULT_PARQUET_PROCESS_DIR "parquet\\s3"
#else
#define DEFAULT_PARQUET_PROCESS_DIR "/tmp/parquet/s3"
#endif /* FLB_SYSTEM_WINDOWS */
#endif

struct flb_s3;

int flb_s3_parquet_compress(struct flb_s3 *ctx,
                            char *body, size_t body_size,
                            void **payload_buf, size_t *payload_size);

#endif
