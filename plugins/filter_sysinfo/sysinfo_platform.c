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
#include <string.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_utils.h>

static int append_key_value_str(struct filter_sysinfo_ctx *ctx,
                                struct flb_log_event_encoder *enc,
                                char *key, char *val)
{
    /* TODO: add kv to metadata ? */

    return flb_log_event_encoder_append_body_values(enc,
             FLB_LOG_EVENT_CSTRING_VALUE(key),
             FLB_LOG_EVENT_CSTRING_VALUE(val));
}

static int sysinfo_append_flb_ver(struct filter_sysinfo_ctx *ctx,
                                   struct flb_log_event_encoder *enc)
{
    return append_key_value_str(ctx, enc, ctx->flb_ver_key, FLB_VERSION_STR);
}

static int sysinfo_append_os_name(struct filter_sysinfo_ctx *ctx,
                                  struct flb_log_event_encoder *enc)
{
    return append_key_value_str(ctx, enc, ctx->os_name_key, flb_utils_get_os_name());
}

static int sysinfo_append_hostname(struct filter_sysinfo_ctx *ctx,
                                   struct flb_log_event_encoder *enc)
{
    int ret;
    char hostname[1024];

    ret = gethostname(&hostname[0], sizeof(hostname)-1);
    if (ret < 0) {
        return append_key_value_str(ctx, enc, ctx->hostname_key, "unknown");
    }
    hostname[sizeof(hostname)-1] = '\0';
    return append_key_value_str(ctx, enc, ctx->hostname_key, &hostname[0]);
}

int flb_sysinfo_append_common_info(struct filter_sysinfo_ctx *ctx,
                                   struct flb_log_event_encoder *enc)
{
    if (ctx->flb_ver_key) {
        sysinfo_append_flb_ver(ctx, enc);
    }
    if (ctx->os_name_key) {
        sysinfo_append_os_name(ctx, enc);
    }
    if (ctx->hostname_key) {
        sysinfo_append_hostname(ctx, enc);
    }

    return 0;
}




/* Platform specific code */
#ifdef __linux__
#include "sysinfo_platform_linux.c"
#else

#include <fluent-bit/flb_filter_plugin.h>

int flb_sysinfo_platform_init(struct filter_sysinfo_ctx *ctx)
{
    if (ctx->os_version_key) {
        flb_plg_warn(ctx->ins, "%s is ignored since this platform doesn't support",
                     ctx->os_version_key);
    }
    if (ctx->kernel_version_key) {
        flb_plg_warn(ctx->ins, "%s is ignored since this platform doesn't support",
                     ctx->kernel_version_key);
    }

    return 0;
}

int flb_sysinfo_platform_filter(struct filter_sysinfo_ctx *ctx,
                                struct flb_log_event_encoder *enc,
                                struct flb_log_event_decoder *dec)
{
    return 0;
}


int flb_sysinfo_platform_exit(struct filter_sysinfo_ctx *ctx)
{
    return 0;
}
#endif
