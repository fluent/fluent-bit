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

#include "sysinfo.h"
#include <sys/utsname.h>
#include <fluent-bit/flb_filter_plugin.h>

static int sysinfo_append_os_version(struct filter_sysinfo_ctx *ctx,
                                     struct flb_log_event_encoder *enc)
{
    struct utsname uts;
    int ret;

    ret = uname(&uts);
    if (ret < 0) {
        return append_key_value_str(ctx, enc, ctx->os_version_key, "unknown");
    }

    return append_key_value_str(ctx, enc, ctx->os_version_key, uts.version);
}

static int sysinfo_append_kernel_version(struct filter_sysinfo_ctx *ctx,
                                         struct flb_log_event_encoder *enc)
{
    struct utsname uts;
    int ret;

    ret = uname(&uts);
    if (ret < 0) {
        return append_key_value_str(ctx, enc, ctx->kernel_version_key, "unknown");
    }

    return append_key_value_str(ctx, enc, ctx->kernel_version_key, uts.release);
}


int flb_sysinfo_platform_init(struct filter_sysinfo_ctx *ctx)
{
    return 0;
}

int flb_sysinfo_platform_filter(struct filter_sysinfo_ctx *ctx,
                                struct flb_log_event_encoder *enc,
                                struct flb_log_event_decoder *dec)
{
    if (ctx->os_version_key) {
        sysinfo_append_os_version(ctx, enc);
    }
    if (ctx->kernel_version_key) {
        sysinfo_append_kernel_version(ctx, enc);
    }

    return 0;
}


int flb_sysinfo_platform_exit(struct filter_sysinfo_ctx *ctx)
{
    return 0;
}
