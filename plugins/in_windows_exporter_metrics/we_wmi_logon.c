/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "we.h"
#include "we_wmi.h"
#include "we_wmi_cpu_info.h"
#include "we_util.h"
#include "we_metric.h"

static double nop_adjust(double value)
{
    return value;
}

int we_wmi_logon_init(struct flb_we *ctx)
{
    ctx->wmi_logon = flb_calloc(1, sizeof(struct we_wmi_logon_counters));
    if (!ctx->wmi_logon) {
        flb_errno();
        return -1;
    }
    ctx->wmi_logon->operational = FLB_FALSE;

    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "windows", "logon", "logon_type",
                         "Number of active logon sessions (LogonSession.LogonType) by WMI Win32_LogonSession",
                         1, (char *[]) {"status"});
    if (!g) {
        return -1;
    }

    ctx->wmi_logon->info = flb_calloc(1, sizeof(struct wmi_query_spec));
    if (!ctx->wmi_logon->info) {
        flb_errno();
        return -1;
    }
    ctx->wmi_logon->info->label_property_keys = (char **) flb_calloc(1, sizeof(char *));
    if (!ctx->wmi_logon->info->label_property_keys) {
        flb_errno();
        return -1;
    }

    ctx->wmi_logon->info->metric_instance = (void *)g;
    ctx->wmi_logon->info->type = CMT_GAUGE;
    ctx->wmi_logon->info->value_adjuster = nop_adjust;
    ctx->wmi_logon->info->wmi_counter = "Win32_LogonSession";
    ctx->wmi_logon->info->wmi_property = "LogonType";
    ctx->wmi_logon->info->label_property_count = 1;
    ctx->wmi_logon->info->label_property_keys[0] = "status" ;
    ctx->wmi_logon->info->where_clause = NULL;

    ctx->wmi_logon->operational = FLB_TRUE;

    return 0;
}

int we_wmi_logon_exit(struct flb_we *ctx)
{
    flb_free(ctx->wmi_logon->info->label_property_keys);
    flb_free(ctx->wmi_logon->info);
    flb_free(ctx->wmi_logon);

    return 0;
}

int we_wmi_logon_update(struct flb_we *ctx)
{
    IEnumWbemClassObject* enumerator = NULL;
    HRESULT hr;

    IWbemClassObject *class_obj = NULL;
    ULONG ret = 0;
    double val = 0;
    int type = 0;
    uint64_t timestamp = 0;
    /* Init counters for logon */
    uint64_t system = 0, interactive = 0, network = 0, batch = 0, service = 0,
        proxy = 0, unlock = 0, networkcleartext = 0, newcredentials = 0, remoteinteractive = 0,
        cachedinteractive = 0, cachedremoteinteractive = 0, cachedunlock = 0;
    struct wmi_query_spec *spec;

    if (!ctx->wmi_logon->operational) {
        flb_plg_error(ctx->ins, "logon collector not yet in operational state");

        return -1;
    }

    if (FAILED(we_wmi_coinitialize(ctx))) {
        return -1;
    }

    timestamp = cfl_time_now();

    if (FAILED(we_wmi_execute_query(ctx, ctx->wmi_logon->info, &enumerator))) {
        return -1;
    }

    while(enumerator) {
        hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1,
                                      &class_obj, &ret);

        if(0 == ret) {
            break;
        }

        val = we_wmi_get_value(ctx, ctx->wmi_logon->info, class_obj);
        type = (int)val;

        switch(type) {
        case 0:
            system++;
            break;
        case 2:
            interactive++;
            break;
        case 3:
            network++;
            break;
        case 4:
            batch++;
            break;
        case 5:
            service++;
            break;
        case 6:
            proxy++;
            break;
        case 7:
            unlock++;
            break;
        case 8:
            networkcleartext++;
            break;
        case 9:
            newcredentials++;
            break;
        case 10:
            remoteinteractive++;
            break;
        case 11:
            cachedinteractive++;
            break;
        case 12:
            cachedremoteinteractive++;
            break;
        case 13:
            cachedunlock++;
            break;
        }

        class_obj->lpVtbl->Release(class_obj);
    }

    enumerator->lpVtbl->Release(enumerator);

    spec = ctx->wmi_logon->info;

    we_wmi_update_counters(ctx, spec, timestamp, (double)system, 1, (char *[]) {"system"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)interactive, 1, (char *[]) {"interactive"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)network, 1, (char *[]) {"network"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)batch, 1, (char *[]) {"batch"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)service, 1, (char *[]) {"service"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)proxy, 1, (char *[]) {"proxy"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)unlock, 1, (char *[]) {"unlock"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)networkcleartext, 1, (char *[]) {"network_clear_text"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)newcredentials, 1, (char *[]) {"new_credentials"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)remoteinteractive, 1, (char *[]) {"remote_interactive"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)cachedinteractive, 1, (char *[]) {"cached_interactive"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)cachedremoteinteractive, 1, (char *[]) {"cached_remote_interactive"} );
    we_wmi_update_counters(ctx, spec, timestamp, (double)cachedunlock, 1, (char *[]) {"cached_unlock"} );

    we_wmi_cleanup(ctx);

    return 0;
}
