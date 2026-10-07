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

#ifndef FLB_MP_PREFLIGHT_H
#define FLB_MP_PREFLIGHT_H

#include <stddef.h>

/* No object allocations are performed while scanning untrusted data.
 * limit caps zone memory; wire_limit independently caps serialized bytes. */
struct flb_mp_preflight;
struct flb_mp_preflight *flb_mp_preflight_create(size_t limit, size_t wire_limit);
void flb_mp_preflight_destroy(struct flb_mp_preflight *scan);
void flb_mp_preflight_reset(struct flb_mp_preflight *scan, size_t limit, size_t wire_limit);
/* Returns 1 for one complete object, 0 for incomplete input, -1 on rejection.
 * Retain the buffer prefix between calls; its address may change.
 */
int flb_mp_preflight_scan(struct flb_mp_preflight *scan, const char *data,
                         size_t len, size_t *consumed, size_t *cost);
/* Validate a complete sequence against a cumulative zone budget. This also
 * bounds decoders that retain earlier objects (for example log group markers).
 * SIZE_MAX preserves structural validation without a practical zone budget. */
int flb_mp_preflight_sequence(const char *data, size_t len, size_t limit);

#endif
