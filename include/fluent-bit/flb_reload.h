/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_RELOAD_H
#define FLB_RELOAD_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_format.h>

#define FLB_RELOAD_IDLE             0
#define FLB_RELOAD_IN_PROGRESS      1
#define FLB_RELOAD_ABORTED         -1
#define FLB_RELOAD_HALTED          -2
#define FLB_RELOAD_NOT_ENABLED     -3
#define FLB_RELOAD_INVALID_CONTEXT -4

int flb_reload_property_check_all(struct flb_config *config);
int flb_reload_reconstruct_cf(struct flb_cf *src_cf, struct flb_cf *dest_cf);
int flb_reload(flb_ctx_t *ctx, struct flb_cf *cf_opts);
int flb_reload_signal_reload(struct flb_config *config);

#endif
