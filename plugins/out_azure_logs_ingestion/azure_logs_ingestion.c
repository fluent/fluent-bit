/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_conf.h"

static int cb_azure_ingestion_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_az_li *ctx;
    (void) config;
    (void) ins;
    (void) data;

    // Allocate and initialize a context from configuration
    ctx = flb_az_li_ctx_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    return 0;
}

static void cb_azure_ingestion_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{

}

static int cb_azure_ingestion_exit(void *data, struct flb_config *config)
{
    struct flb_azure *ctx = data;

    flb_azure_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "tenant_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_az_li, tenant_id),
     "Set the tenant ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_az_li, client_id),
     "Set the client/app ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_secret", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_az_li, client_secret),
     "Set the client secret of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "dce_url", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_az_li, dce_url),
     "Data Collection Endpoint(DCE) URI (e.g. "
     "https://la-endpoint-q57l.eastus-1.ingest.monitor.azure.com)"
    },
    {
     FLB_CONFIG_MAP_STR, "dcr_id", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_az_li, dcr_id),
     "Data Collection Rule (DCR) immutable ID"
    },
    {
     FLB_CONFIG_MAP_STR, "table_name", (char *)NULL, 0, FLB_TRUE,
     offsetof(struct flb_az_li, table_name),
     "The name of the custom log table, including '_CL' suffix"
    },
    /* optional params */
    {
     FLB_CONFIG_MAP_STR, "time_key", FLB_AZ_LI_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_az_li, time_key),
     "[Optional] Specify the key name where the timestamp will be stored."
    },

    {
     FLB_CONFIG_MAP_BOOL, "time_generated", "false",
     0, FLB_TRUE, offsetof(struct flb_az_li, time_generated),
     "If enabled, will generate a timestamp and append it to JSON. "
     "The key name is set by the 'time_key' parameter"
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_azure_logs_ingestion_plugin = {
    .name         = "azure_logs_ingestion",
    .description  = "Send logs to Log Analytics with Log Ingestion API",
    .cb_init      = cb_azure_ingestion_init,
    .cb_flush     = cb_azure_ingestion_flush,
    .cb_exit      = cb_azure_ingestion_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
