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

#ifndef FLB_KAFKA_PROTOBUF_H
#define FLB_KAFKA_PROTOBUF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define FLB_KAFKA_PROTOBUF_NOEXCEPT noexcept
extern "C" {
#else
#define FLB_KAFKA_PROTOBUF_NOEXCEPT
#endif

struct flb_kafka_protobuf;

/* No C++ exceptions may escape this interface. Fallible operations catch exceptions
 * and return NULL or -1. Free and destroy are non-throwing cleanup operations.
 * All returned payloads use malloc; release with flb_kafka_protobuf_free().
 */
struct flb_kafka_protobuf *flb_kafka_protobuf_create(void) FLB_KAFKA_PROTOBUF_NOEXCEPT;
int flb_kafka_protobuf_add(struct flb_kafka_protobuf *ctx, const char *name,
                         const char *schema, size_t size) FLB_KAFKA_PROTOBUF_NOEXCEPT;
int flb_kafka_protobuf_compile(struct flb_kafka_protobuf *ctx, const char *message,
                             char *error, size_t error_size) FLB_KAFKA_PROTOBUF_NOEXCEPT;
int flb_kafka_protobuf_encode(struct flb_kafka_protobuf *ctx, int32_t schema_id,
                            const char *json, size_t json_size,
                            char **out, size_t *out_size, char *error, size_t error_size)
                            FLB_KAFKA_PROTOBUF_NOEXCEPT;
void flb_kafka_protobuf_free(void *payload) FLB_KAFKA_PROTOBUF_NOEXCEPT;
void flb_kafka_protobuf_destroy(struct flb_kafka_protobuf *ctx) FLB_KAFKA_PROTOBUF_NOEXCEPT;

#define FLB_KAFKA_PROTOBUF_ROOT "__fluent_bit_root.proto"
#define FLB_KAFKA_PROTOBUF_MAX_FILES 64
#define FLB_KAFKA_PROTOBUF_MAX_SCHEMA_BYTES (4 * 1024 * 1024)

#ifdef __cplusplus
}
#endif
#undef FLB_KAFKA_PROTOBUF_NOEXCEPT
#endif
