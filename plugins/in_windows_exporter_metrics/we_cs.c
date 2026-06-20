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
#include "we_cs.h"
#include "we_util.h"
#include "we_metric.h"

int we_cs_init(struct flb_we *ctx)
{
    ctx->cs.operational = FLB_FALSE;

    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "windows", "cs", "logical_processors",
                         "Number of logical processors",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->cs.logical_processors = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "cs", "physical_memory_bytes",
                         "Amount of bytes of physical memory",
                         0, NULL);

    if (!g) {
        return -1;
    }
    ctx->cs.physical_memory_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "windows", "cs", "hostname",
                         "Value of Local Time",
                         3, (char *[]) {"hostname", "domain", "fqdn"});
    if (!g) {
        return -1;
    }
    ctx->cs.hostname = g;

    ctx->cs.operational = FLB_TRUE;

    return 0;
}

int we_cs_exit(struct flb_we *ctx)
{
    return 0;
}

int we_cs_update(struct flb_we *ctx)
{
    SYSTEM_INFO system_info;
    MEMORYSTATUSEX statex;
    char hostname[256] = "", domain[256] = "", fqdn[256] = "";
    DWORD size = 0;
    uint64_t timestamp = 0;

    if (!ctx->cs.operational) {
        flb_plg_error(ctx->ins, "cs collector not yet in operational state");

        return -1;
    }

    timestamp = cfl_time_now();

    statex.dwLength = sizeof (statex);
    GlobalMemoryStatusEx(&statex);

    GetSystemInfo(&system_info);

    size = _countof(hostname);
    if (!GetComputerNameExA(ComputerNameDnsHostname, hostname, &size)) {
        flb_plg_warn(ctx->ins, "Failed to retrieve hostname info");
    }
    size = _countof(domain);
    if (!GetComputerNameExA(ComputerNameDnsDomain, domain, &size)) {
        flb_plg_warn(ctx->ins, "Failed to retrieve domain info");
    }
    size = _countof(fqdn);
    if (!GetComputerNameExA(ComputerNameDnsFullyQualified, fqdn, &size)) {
        flb_plg_warn(ctx->ins, "Failed to retrieve fqdn info");
    }

    cmt_gauge_set(ctx->cs.logical_processors, timestamp, (double)system_info.dwNumberOfProcessors, 0, NULL);
    cmt_gauge_set(ctx->cs.physical_memory_bytes, timestamp, (double)statex.ullTotalPhys, 0, NULL);
    cmt_gauge_set(ctx->cs.hostname, timestamp, 1.0, 3, (char *[]) { hostname, domain, fqdn });

    return 0;
}
