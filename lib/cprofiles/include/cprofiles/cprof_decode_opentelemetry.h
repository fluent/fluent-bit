/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  ========
 *  Copyright 2024 The CProfiles Authors
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

#ifndef CPROF_DECODE_OPENTELEMETRY_H
#define CPROF_DECODE_OPENTELEMETRY_H

#include <cprofiles/cprofiles.h>
#include <opentelemetry/proto/profiles/v1development/profiles.pb-c.h>
#include <opentelemetry/proto/collector/profiles/v1development/profiles_service.pb-c.h>

#define CPROF_DECODE_OPENTELEMETRY_SUCCESS                0
#define CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR       1
#define CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR 2

struct crof_opentelemetry_decode_context {
    struct cprof *inner_context;
};

int cprof_decode_opentelemetry_create(struct cprof **result_context,
                                      unsigned char *in_buf,
                                      size_t in_size,
                                      size_t *offset);

void cprof_decode_opentelemetry_destroy(struct cprof *context);

#endif
