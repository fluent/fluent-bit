/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */

/* Test functions */
void flb_test_azure_kusto_json_invalid(void);
void flb_test_azure_kusto_managed_identity_system(void);
void flb_test_azure_kusto_managed_identity_user(void);
void flb_test_azure_kusto_service_principal(void);
void flb_test_azure_kusto_workload_identity(void);
void flb_test_azure_kusto_cloud_global_inference(void);
void flb_test_azure_kusto_cloud_china_inference(void);

/* Test list */
TEST_LIST = {
    {"json_invalid", flb_test_azure_kusto_json_invalid},
    {"managed_identity_system", flb_test_azure_kusto_managed_identity_system},
    {"managed_identity_user", flb_test_azure_kusto_managed_identity_user},
    {"service_principal", flb_test_azure_kusto_service_principal},
    {"workload_identity", flb_test_azure_kusto_workload_identity},
    {"cloud_global_inference", flb_test_azure_kusto_cloud_global_inference},
    {"cloud_china_inference", flb_test_azure_kusto_cloud_china_inference},
    {NULL, NULL}
};

void flb_test_azure_kusto_json_invalid(void)
{
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
        total++;
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for system-assigned managed identity */
void flb_test_azure_kusto_managed_identity_system(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for user-assigned managed identity */
void flb_test_azure_kusto_managed_identity_user(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "00000000-0000-0000-0000-000000000000", NULL);  /* Example UUID */
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for service principal authentication */
void flb_test_azure_kusto_service_principal(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "service_principal", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for workload identity authentication */
void flb_test_azure_kusto_workload_identity(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "workload_identity", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "workload_identity_token_file", "/path/to/token/file", NULL);
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for cloud inference: "Global", based on ingestion_endpoint */
void flb_test_azure_kusto_cloud_global_inference(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "service_principal", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    /* Global ingestion endpoint */
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.windows.net", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for cloud inference: "China", based on ingestion_endpoint */
void flb_test_azure_kusto_cloud_china_inference(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_kusto", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "service_principal", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    /* China ingestion endpoint */
    flb_output_set(ctx, out_ffd, "ingestion_endpoint", "https://ingest-CLUSTER.kusto.chinacloudapi.cn", NULL);
    flb_output_set(ctx, out_ffd, "database_name", "telemetrydb", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "logs", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}
