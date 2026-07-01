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

#ifndef FLB_GZIP_H
#define FLB_GZIP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <monkey/mk_http.h>

struct flb_decompression_context;

int flb_gzip_compress(void *in_data, size_t in_len,
                      void **out_data, size_t *out_len);
int flb_gzip_uncompress(void *in_data, size_t in_len,
                        void **out_data, size_t *out_size);

/*
 * Uncompress a gzip payload with trailing data. On success in_remaining is set to the number
 * of input bits not part of the first gzip payload.
 */
int flb_gzip_uncompress_multi(void *in_data, size_t in_len,
                        void **out_data, size_t *out_size, size_t *in_remaining);

void *flb_gzip_decompression_context_create();
void flb_gzip_decompression_context_destroy(void *context);

int flb_gzip_decompressor_dispatch(struct flb_decompression_context *context,
                                   void *out_data, size_t *out_size);

int flb_is_http_session_gzip_compressed(struct mk_http_session *session);

#endif
