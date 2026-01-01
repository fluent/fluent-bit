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

#ifndef FLB_FILTER_SYSINFO_H
#define FLB_FILTER_SYSINFO_H

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_sds.h>

struct filter_sysinfo_ctx {
    struct flb_filter_instance *ins;

    flb_sds_t flb_ver_key;
    flb_sds_t os_name_key;
    flb_sds_t hostname_key;

    /* Platform specific */
    flb_sds_t os_version_key;
    flb_sds_t kernel_version_key;
};

int flb_sysinfo_append_common_info(struct filter_sysinfo_ctx *ctx,
                                   struct flb_log_event_encoder *enc);


/* Platform specific API */
int flb_sysinfo_platform_init(struct filter_sysinfo_ctx *ctx);
int flb_sysinfo_platform_filter(struct filter_sysinfo_ctx *ctx,
                                struct flb_log_event_encoder *enc,
                                struct flb_log_event_decoder *dec);
int flb_sysinfo_platform_exit(struct filter_sysinfo_ctx *ctx);

#endif
