/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_mib.h>

static int netdev_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "receive_packets",
                         "network information for receive_packets",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_receive_packets = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "transmit_packets",
                         "network information for transmit_packets",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_transmit_packets = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "receive_bytes",
                         "network information for receive_bytes",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_receive_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "transmit_bytes",
                         "network information for transmit_bytes",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_transmit_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "receive_errors",
                         "network information for receive_errors",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_receive_errors = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "transmit_errors",
                         "network information for transmit_errors",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_transmit_errors = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "receive_dropped",
                         "network information for receive_dropped",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_receive_dropped = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "receive_multicast",
                         "network information for receive_multicast",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_receive_multicast = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "transmit_multicast",
                         "network information for transmit_multicast",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_transmit_multicast = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "collisions",
                         "network information for collisions",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_collisions = g;

    g = cmt_gauge_create(ctx->cmt, "node", "network", "noproto",
                         "network information for noproto",
                         1, (char *[]){ "device" });
    if (!g) {
        return -1;
    }
    ctx->darwin_noproto = g;

    return 0;
}

static int netdev_update(struct flb_ne *ctx)
{
    int ret;
    int i;
    int if_count;
    size_t clen = sizeof(if_count);
    int cmib[] = { CTL_NET, PF_LINK, NETLINK_GENERIC, IFMIB_SYSTEM, IFMIB_IFCOUNT };
    int mib[6];
    struct ifmibdata ifmd;
    size_t ifmd_len = sizeof(ifmd);
    char ifname[IF_NAMESIZE];
    uint64_t ts;

    ts = cfl_time_now();

    ret = sysctl(cmib, 5, &if_count, &clen, NULL, 0);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "failed to get count of interface(s) for network");
        return -1;
    }

    for (i = 1; i <= if_count; i++) {
        mib[0] = CTL_NET;
        mib[1] = PF_LINK;
        mib[2] = NETLINK_GENERIC;
        mib[3] = IFMIB_IFDATA;
        mib[4] = i;
        mib[5] = IFDATA_GENERAL;

        /* Receive network metrics with struct ifmibdata.
         * ref: https://developer.apple.com/documentation/kernel/ifmibdata/3753765-ifmd_data?changes=_5
         */
        ret = sysctl(mib, 6, &ifmd, &ifmd_len, NULL, 0);
        if (ret < 0) {
            continue;
        }

        if (!if_indextoname(i, ifname)) {
            flb_plg_debug(ctx->ins, "failed to if_index_toname for %d", i);
            snprintf(ifname, IF_NAMESIZE, "(unknown %i)", i);
        }

        cmt_gauge_set(ctx->darwin_receive_packets, ts,
                      (double)ifmd.ifmd_data.ifi_ipackets, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_transmit_packets, ts,
                      (double)ifmd.ifmd_data.ifi_opackets, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_receive_bytes, ts,
                      (double)ifmd.ifmd_data.ifi_ibytes, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_transmit_bytes, ts,
                      (double)ifmd.ifmd_data.ifi_obytes, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_receive_errors, ts,
                      (double)ifmd.ifmd_data.ifi_ierrors, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_transmit_errors, ts,
                      (double)ifmd.ifmd_data.ifi_oerrors, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_receive_dropped, ts,
                      (double)ifmd.ifmd_data.ifi_iqdrops, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_receive_multicast, ts,
                      (double)ifmd.ifmd_data.ifi_imcasts, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_transmit_multicast, ts,
                      (double)ifmd.ifmd_data.ifi_imcasts, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_collisions, ts,
                      (double)ifmd.ifmd_data.ifi_collisions, 1, (char *[]) { ifname });

        cmt_gauge_set(ctx->darwin_noproto, ts,
                      (double)ifmd.ifmd_data.ifi_noproto, 1, (char *[]) { ifname });

    }

    return 0;
}

static int ne_netdev_init(struct flb_ne *ctx)
{
    netdev_configure(ctx);
    return 0;
}

static int ne_netdev_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    netdev_update(ctx);
    return 0;
}

static int ne_netdev_exit(struct flb_ne *ctx)
{
    return 0;
}

struct flb_ne_collector netdev_collector = {
    .name = "netdev",
    .cb_init = ne_netdev_init,
    .cb_update = ne_netdev_update,
    .cb_exit = ne_netdev_exit
};
