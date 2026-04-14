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

#ifndef FLB_PROCESSOR_CONTENT_MODIFIER_OTEL_H
#define FLB_PROCESSOR_CONTENT_MODIFIER_OTEL_H

#include <cfl/cfl.h>

struct cfl_variant *cm_otel_get_or_create_attributes(struct cfl_kvlist *kvlist);
struct cfl_variant *cm_otel_get_attributes(int telemetry_type, int context, struct cfl_kvlist *kvlist);
struct cfl_variant *cm_otel_get_scope_metadata(int telemetry_type, struct cfl_kvlist *kvlist);

#endif
