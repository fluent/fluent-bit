/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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

#include <stdio.h>
#include <fluent-otel-proto/fluent-otel.h>

/* just a way to expose some helper functions */
void fluent_otel_info()
{

    printf("- opentelemetry proto 'common'  : ");
#ifdef FLUENT_OTEL_HAVE_COMMON
    printf("%10s", "found\n");
#else
    printf("%10s", "not found (enable it with -DFLUENT_PROTO_COMMON)\n");
#endif

    printf("- opentelemetry proto 'resource': ");
#ifdef FLUENT_OTEL_HAVE_RESOURCE
    printf("%10s", "found\n");
#else
    printf("%10s", "not found (enable it with -DFLUENT_PROTO_RESOURCE)\n");
#endif

    printf("- opentelemetry proto 'trace'   : ");
#ifdef FLUENT_OTEL_HAVE_TRACE
    printf("%10s", "found\n");
#else
    printf("%10s", "not found (enable it with -DFLUENT_PROTO_TRACE)\n");
#endif

    printf("- opentelemetry proto 'logs'    : ");
#ifdef FLUENT_OTEL_HAVE_LOGS
    printf("%10s", "found\n");
#else
    printf("%10s", "not found (enable it with -DFLUENT_PROTO_LOGS)\n");
#endif

    printf("- opentelemetry proto 'metrics' : ");
#ifdef FLUENT_OTEL_HAVE_METRICS
    printf("%10s", "found\n");
#else
    printf("%10s", "not found (enable it with -DFLUENT_PROTO_METRICS)\n");
#endif

}
