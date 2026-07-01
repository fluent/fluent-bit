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

#ifndef FLB_OUT_PROMETHEUS_REMOTE_WRITE_CONF_H
#define FLB_OUT_PROMETHEUS_REMOTE_WRITE_CONF_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>

#include "remote_write.h"

struct prometheus_remote_write_context *flb_prometheus_remote_write_context_create(
    struct flb_output_instance *ins, struct flb_config *config);
void flb_prometheus_remote_write_context_destroy(
    struct prometheus_remote_write_context *ctx);

#endif
