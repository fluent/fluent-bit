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

#ifndef FLUENT_OTEL_PROTO_H
#define FLUENT_OTEL_PROTO_H

#include <fluent-otel-proto/fluent-otel-info.h>

#ifdef FLUENT_OTEL_HAVE_COMMON
#include <opentelemetry/proto/common/v1/common.pb-c.h>
#endif

#ifdef FLUENT_OTEL_HAVE_RESOURCE
#include <opentelemetry/proto/resource/v1/resource.pb-c.h>
#endif

#ifdef FLUENT_OTEL_HAVE_TRACE
#include <opentelemetry/proto/trace/v1/trace.pb-c.h>
#include <opentelemetry/proto/collector/trace/v1/trace_service.pb-c.h>
#endif

#ifdef FLUENT_OTEL_HAVE_LOGS
#include <opentelemetry/proto/logs/v1/logs.pb-c.h>
#include <opentelemetry/proto/collector/logs/v1/logs_service.pb-c.h>
#endif

#ifdef FLUENT_OTEL_HAVE_METRICS
#include <opentelemetry/proto/metrics/v1/metrics.pb-c.h>
#include <opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h>
#endif

/* just a way to expose some helper functions */
void fluent_otel_info();

#endif