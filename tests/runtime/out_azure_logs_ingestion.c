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

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */

/* Test functions */
void flb_test_azure_logs_ingestion_json_invalid(void);
void flb_test_azure_logs_ingestion_managed_identity_system(void);
void flb_test_azure_logs_ingestion_managed_identity_user(void);
void flb_test_azure_logs_ingestion_managed_identity_missing_client_id(void);
void flb_test_azure_logs_ingestion_service_principal_explicit(void);
void flb_test_azure_logs_ingestion_service_principal_default(void);
void flb_test_azure_logs_ingestion_service_principal_missing_client_id(void);
void flb_test_azure_logs_ingestion_service_principal_missing_client_secret(void);
void flb_test_azure_logs_ingestion_service_principal_missing_tenant_id(void);
void flb_test_azure_logs_ingestion_invalid_auth_type(void);

/* Test list */
TEST_LIST = {
    {"json_invalid", flb_test_azure_logs_ingestion_json_invalid},
    {"managed_identity_system", flb_test_azure_logs_ingestion_managed_identity_system},
    {"managed_identity_user", flb_test_azure_logs_ingestion_managed_identity_user},
    {"managed_identity_missing_client_id", flb_test_azure_logs_ingestion_managed_identity_missing_client_id},
    {"service_principal_explicit", flb_test_azure_logs_ingestion_service_principal_explicit},
    {"service_principal_default", flb_test_azure_logs_ingestion_service_principal_default},
    {"service_principal_missing_client_id", flb_test_azure_logs_ingestion_service_principal_missing_client_id},
    {"service_principal_missing_client_secret", flb_test_azure_logs_ingestion_service_principal_missing_client_secret},
    {"service_principal_missing_tenant_id", flb_test_azure_logs_ingestion_service_principal_missing_tenant_id},
    {"auth_type_invalid", flb_test_azure_logs_ingestion_invalid_auth_type},
    {NULL, NULL}
};

void flb_test_azure_logs_ingestion_json_invalid(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

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
void flb_test_azure_logs_ingestion_managed_identity_system(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for user-assigned managed identity */
void flb_test_azure_logs_ingestion_managed_identity_user(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "00000000-0000-0000-0000-000000000000", NULL);  /* Example UUID */
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for failure if user-assigned managed identity is used without client_id*/
void flb_test_azure_logs_ingestion_managed_identity_missing_client_id(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for service principal authentication with explicit auth_type*/
void flb_test_azure_logs_ingestion_service_principal_explicit(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "service_principal", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for default service principal authentication with empty auth_type*/
void flb_test_azure_logs_ingestion_service_principal_default(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for failure in case of missing client_id for auth_type service_principal*/
void flb_test_azure_logs_ingestion_service_principal_missing_client_id(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for failure in case of missing client_secret for auth_type service_principal*/
void flb_test_azure_logs_ingestion_service_principal_missing_client_secret(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for failure in case of missing tenant_id for auth_type service_principal*/
void flb_test_azure_logs_ingestion_service_principal_missing_tenant_id(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for failure in case of invalid auth_type*/
void flb_test_azure_logs_ingestion_invalid_auth_type(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_logs_ingestion", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "INVALID", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "your-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "your-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "your-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "dce_url", "https://test-dce.eastus-1.ingest.monitor.azure.com", NULL);
    flb_output_set(ctx, out_ffd, "dcr_id", "dcr-00000000000000000000000000000000", NULL);
    flb_output_set(ctx, out_ffd, "table_name", "TestTable_CL", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}
