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

#ifndef FLB_OUT_S3_PROTOBUF_H
#define FLB_OUT_S3_PROTOBUF_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_event.h>

#include "s3.h"

int s3_protobuf_configure(struct flb_s3 *ctx);
void s3_protobuf_destroy(struct flb_s3 *ctx);

flb_sds_t s3_protobuf_format_event_chunk(
                                struct flb_s3 *ctx,
                                struct flb_event_chunk *event_chunk);

int s3_protobuf_compress_columnar(struct flb_s3 *ctx,
                                  int columnar_format,
                                  const void *buffer, size_t buffer_size,
                                  void **out_buffer, size_t *out_size,
                                  int compression_type,
                                  char *error, size_t error_size);

#endif
