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

#ifndef FLB_IN_OPENTELEMETRY_TRACES_H
#define FLB_IN_OPENTELEMETRY_TRACES_H

#include <fluent-bit/flb_input_plugin.h>

int opentelemetry_traces_process_protobuf(struct flb_opentelemetry *ctx,
                                          flb_sds_t tag,
                                          size_t tag_len,
                                          void *data, size_t size);

int opentelemetry_traces_process_raw_traces(struct flb_opentelemetry *ctx,
                                            flb_sds_t tag,
                                            size_t tag_len,
                                            void *data, size_t size);

int opentelemetry_process_traces(struct flb_opentelemetry *ctx,
                                 flb_sds_t content_type,
                                 flb_sds_t tag,
                                 size_t tag_len,
                                 void *data, size_t size);

#endif