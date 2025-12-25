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

/*
 * Convert msgpack raw data to Apache Parquet format with automatic memory allocation.
 * Schema must be provided by the user in Arrow's JSON schema format.
 *
 * The function uses Arrow's BufferOutputStream for automatic memory management,
 * eliminating the need for buffer size estimation.
 *
 * @param in_buf      Msgpack raw data buffer
 * @param in_size     Size of msgpack data
 * @param schema_str  Arrow JSON schema string (uses Arrow's Schema::FromJSON)
 *                    Format: {"fields":[{"name":"field1","type":{"name":"utf8"},"nullable":true},...]}
 *
 *                    Type specification format:
 *                    - Simple types: {"name":"utf8"}, {"name":"int64"}, {"name":"float64"}
 *                    - With parameters: {"name":"timestamp","unit":"MICROSECOND"}
 *                    - List: {"name":"list","children":[{"type":{"name":"utf8"}}]}
 *                    - Struct: {"name":"struct","children":[{"name":"field1","type":{...}},...]}
 *
 *                    Supported types: null, bool, int8, int16, int32, int64, uint8, uint16,
 *                                    uint32, uint64, halffloat, float, double, utf8, binary,
 *                                    large_utf8, large_binary, date32, date64, timestamp,
 *                                    time32, time64, duration, decimal, list, large_list,
 *                                    fixed_size_list, struct, map, union, dictionary
 *
 *                    Field attributes:
 *                    - nullable: (optional, default: true) Whether field can be null
 *                    - metadata: (optional) Key-value pairs for field metadata
 *
 *                    See Arrow documentation for complete schema specification:
 *                    https://arrow.apache.org/docs/format/Schema.html
 *
 * @param compression Compression type (FLB_AWS_COMPRESS_*)
 * @param out_size    Output: actual Parquet data size
 * @return            Pointer to allocated Parquet buffer (caller must free with flb_free),
 *                    or NULL on failure
 *
 * Example usage:
 *   const char *schema =
 *       "{\"fields\":["
 *       "{\"name\":\"message\",\"type\":{\"name\":\"utf8\"},\"nullable\":true},"
 *       "{\"name\":\"level\",\"type\":{\"name\":\"int32\"},\"nullable\":false},"
 *       "{\"name\":\"timestamp\",\"type\":{\"name\":\"timestamp\",\"unit\":\"MICROSECOND\"}}"
 *       "]}";
 *   size_t parquet_size = 0;
 *   void *parquet_buf = flb_msgpack_raw_to_parquet(
 *       msgpack_data, msgpack_size,
 *       schema,
 *       FLB_AWS_COMPRESS_SNAPPY,
 *       &parquet_size
 *   );
 *   if (parquet_buf) {
 *       // Use parquet_buf...
 *       flb_free(parquet_buf);
 *   }
 */
void *flb_msgpack_raw_to_parquet(const void *in_buf, size_t in_size,
                                  const char *schema_str,
                                  int compression,
                                  size_t *out_size);

#endif
