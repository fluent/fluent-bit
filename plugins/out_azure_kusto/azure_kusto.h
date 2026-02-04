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

#ifndef FLB_OUT_AZURE_KUSTO
#define FLB_OUT_AZURE_KUSTO

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream_ha.h>

#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <sys/stat.h>
#include <fcntl.h>

/* refresh token every 50 minutes */
#define FLB_AZURE_KUSTO_TOKEN_REFRESH 3000

/* Authentication types */
typedef enum {
    FLB_AZURE_KUSTO_AUTH_SERVICE_PRINCIPAL = 0,   /* Client ID + Client Secret */
    FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_SYSTEM, /* System-assigned managed identity */
    FLB_AZURE_KUSTO_AUTH_MANAGED_IDENTITY_USER,   /* User-assigned managed identity */
    FLB_AZURE_KUSTO_AUTH_WORKLOAD_IDENTITY        /* Workload Identity */
} flb_azure_kusto_auth_type;

/* Kusto streaming inserts oauth scope */
#define FLB_AZURE_KUSTO_SCOPE "https://help.kusto.windows.net/.default"

/* MSAL authorization URL  */
#define FLB_MSAL_AUTH_URL_TEMPLATE \
    "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

#define FLB_AZURE_KUSTO_MGMT_URI_PATH "/v1/rest/mgmt"
#define FLB_AZURE_KUSTO_MGMT_BODY_TEMPLATE "{\"csl\":\"%s\", \"db\": \"NetDefaultDB\"}"

#define FLB_AZURE_KUSTO_DEFAULT_TIME_KEY "timestamp"
#define FLB_AZURE_KUSTO_DEFAULT_TAG_KEY "tag"
#define FLB_AZURE_KUSTO_DEFAULT_LOG_KEY "log"

#define AZURE_KUSTO_RESOURCE_STORAGE 0
#define AZURE_KUSTO_RESOURCE_QUEUE 1

#define AZURE_KUSTO_RESOURCE_UPSTREAM_URI "uri"
#define AZURE_KUSTO_RESOURCE_UPSTREAM_SAS "sas"

#define FLB_AZURE_KUSTO_RESOURCES_LOAD_INTERVAL_SEC "3600"

#define FLB_AZURE_KUSTO_INGEST_ENDPOINT_CONNECTION_TIMEOUT "60"

#define FLB_AZURE_KUSTO_BUFFER_DIR_MAX_SIZE "8G"  /* 8GB buffer directory size */
#define UPLOAD_TIMER_MAX_WAIT 180000
#define UPLOAD_TIMER_MIN_WAIT 18000
#define MAX_FILE_SIZE         4000000000 /* 4GB */

#define FLB_AZURE_IMDS_ENDPOINT "/metadata/identity/oauth2/token"
#define FLB_AZURE_IMDS_API_VERSION "2018-02-01"
#define FLB_AZURE_IMDS_RESOURCE "https://api.kusto.windows.net/"


struct flb_azure_kusto_resources {
    struct flb_upstream_ha *blob_ha;
    struct flb_upstream_ha *queue_ha;
    flb_sds_t identity_token;

    /* used to reload resouces after some time */
    uint64_t load_time;

    /* Old resources pending cleanup - deferred destruction to avoid use-after-free
     * when other threads may still be using them during high-volume operations */
    struct flb_upstream_ha *old_blob_ha;
    struct flb_upstream_ha *old_queue_ha;
    flb_sds_t old_identity_token;
};

struct flb_azure_kusto {
    /* azure_kusto configuration */
    flb_sds_t tenant_id;
    flb_sds_t client_id;
    flb_sds_t client_secret;
    flb_sds_t managed_identity_client_id;
    flb_sds_t ingestion_endpoint;
    flb_sds_t database_name;
    flb_sds_t table_name;
    flb_sds_t ingestion_mapping_reference;

    int ingestion_endpoint_connect_timeout;
    int io_timeout;

    /* Authentication */
    int auth_type;
    char *auth_type_str;
    char *workload_identity_token_file;

    /* compress payload */
    int compression_enabled;

    int ingestion_resources_refresh_interval;

    /* records configuration */
    flb_sds_t log_key;
    int include_tag_key;
    flb_sds_t tag_key;
    int include_time_key;
    flb_sds_t time_key;

    flb_sds_t azure_kusto_buffer_key;

    /* --- internal data --- */

    /* oauth2 context */
    flb_sds_t oauth_url;
    struct flb_oauth2 *o;

    int timer_created;
    int timer_ms;

    /* mutex for acquiring oauth tokens */
    pthread_mutex_t token_mutex;

    /* ingestion resources */
    struct flb_azure_kusto_resources *resources;

    /* mutex for loading reosurces */
    pthread_mutex_t resources_mutex;

    pthread_mutex_t blob_mutex;

    pthread_mutex_t buffer_mutex;

    int buffering_enabled;

    size_t file_size;
    time_t upload_timeout;
    time_t retry_time;

    int buffer_file_delete_early;
    int unify_tag;
    int blob_uri_length;
    int scheduler_max_retries;
    int delete_on_max_upload_error;

    int has_old_buffers;
    size_t store_dir_limit_size;
    /* track the total amount of buffered data */
    size_t current_buffer_size;
    flb_sds_t buffer_dir;
    char *store_dir;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream_active;  /* default active stream */
    struct flb_fstore_stream *stream_upload;


    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    struct flb_upstream *imds_upstream;

    /* Fluent Bit context */
    struct flb_config *config;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

flb_sds_t get_azure_kusto_token(struct flb_azure_kusto *ctx);
flb_sds_t execute_ingest_csl_command(struct flb_azure_kusto *ctx, const char *csl);

#endif