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

 #ifndef FLB_IN_OPENTELEMETRY_LOGS_H
 #define FLB_IN_OPENTELEMETRY_LOGS_H

 #include <fluent-bit/flb_input_plugin.h>

int opentelemetry_process_logs(struct flb_opentelemetry *ctx,
                               flb_sds_t content_type,
                               flb_sds_t tag,
                               size_t tag_len,
                               void *data, size_t size);

/*
 * Protobuf logs straight from the encoded request, for a request that was not
 * validated beforehand. '*handled' stays FLB_FALSE when the request has to be
 * validated and processed by opentelemetry_process_logs_with_budget().
 */
int opentelemetry_process_logs_direct(struct flb_opentelemetry *ctx,
                                      flb_sds_t tag,
                                      void *data, size_t size,
                                      size_t *remaining, int *handled);

int opentelemetry_process_logs_with_budget(struct flb_opentelemetry *ctx,
                                           flb_sds_t content_type,
                                           flb_sds_t tag, size_t tag_len,
                                           void *data, size_t size,
                                           size_t *remaining);

#endif
