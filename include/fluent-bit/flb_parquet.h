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

#ifndef FLB_PARQUET_H
#define FLB_PARQUET_H

#include <fluent-bit/flb_sds.h>
#include <msgpack.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Validate Parquet schema at startup (Fail Fast)
 *
 * @param schema_str    JSON schema string to validate
 * @param error_msg     Output buffer for error message (optional)
 * @param error_msg_size Size of error buffer
 * @return              0 on success, -1 on failure
 */
int flb_parquet_validate_schema(const char *schema_str,
                                 char *error_msg,
                                 size_t error_msg_size);

/*
 * Opaque handle for Parquet schema
 * This provides type safety while keeping implementation details hidden
 */
typedef struct flb_parquet_schema flb_parquet_schema;

/*
 * Create Parquet schema from JSON (avoids stack overflow in coroutine)
 *
 * This function parses the JSON schema in the main thread context where
 * stack space is not limited, avoiding stack overflow when yyjson recursively
 * parses deeply nested schemas in Fluent Bit's small coroutine stacks (37KB).
 *
 * @param schema_str    JSON schema string
 * @param error_msg     Output buffer for error message (optional)
 * @param error_msg_size Size of error buffer
 * @return              Schema handle, or NULL on failure
 */
flb_parquet_schema *flb_parquet_schema_create(const char *schema_str,
                                               char *error_msg,
                                               size_t error_msg_size);

/*
 * Free Parquet schema
 *
 * @param schema Schema handle returned by flb_parquet_schema_create
 */
void flb_parquet_schema_destroy(flb_parquet_schema *schema);

/*
 * Convert msgpack to Parquet using streaming approach
 *
 * This function accepts a pre-parsed schema to avoid stack overflow
 * in coroutines. Use flb_parquet_schema_create() during plugin
 * initialization to create the schema.
 *
 * @param msgpack_file_path Path to the msgpack file to read
 * @param schema            Pre-parsed schema from flb_parquet_schema_create()
 * @param compression       Compression type (FLB_AWS_COMPRESS_*)
 * @param output_file       Path where the Parquet file will be written
 * @param out_file_size     Output: size of the generated Parquet file
 * @param total_file_size   Configured total_file_size for optimization
 * @return                  0 on success, -1 on failure
 */
int flb_msgpack_to_parquet_streaming(const char *msgpack_file_path,
                                      flb_parquet_schema *schema,
                                      int compression,
                                      const char *output_file,
                                      size_t *out_file_size,
                                      size_t total_file_size);

#ifdef __cplusplus
}
#endif

#endif
