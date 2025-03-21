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

#ifndef CPROF_ENCODE_OPENTELEMETRY_H
#define CPROF_ENCODE_OPENTELEMETRY_H

#include <cprofiles/cprofiles.h>
#include <opentelemetry/proto/profiles/v1development/profiles.pb-c.h>
#include <opentelemetry/proto/collector/profiles/v1development/profiles_service.pb-c.h>

#define CPROF_ENCODE_OPENTELEMETRY_SUCCESS                0
#define CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR       1
#define CPROF_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR 2
#define CPROF_ENCODE_OPENTELEMETRY_INTERNAL_ENCODER_ERROR 3
#define CPROF_ENCODE_OPENTELEMETRY_UNIDENTIFIED_ERROR     99

struct cprof_opentelemetry_encoding_context {
    struct cprof   *inner_context;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest \
                   *export_service_request;
    //char           *output_buffer;
    //size_t          output_size;
};

int cprof_encode_opentelemetry_create(cfl_sds_t *result_buffer,
                                      struct cprof *profile);

void cprof_encode_opentelemetry_destroy(cfl_sds_t instance);

#endif
