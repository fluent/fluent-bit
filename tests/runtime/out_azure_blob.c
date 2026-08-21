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

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test functions */
#ifdef FLB_HAVE_TLS
void flb_test_azure_blob_managed_identity_system(void);
void flb_test_azure_blob_managed_identity_user(void);
void flb_test_azure_blob_service_principal(void);
void flb_test_azure_blob_workload_identity(void);
#endif
void flb_test_azure_blob_shared_key(void);
void flb_test_azure_blob_sas_token(void);

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_TLS
    {"managed_identity_system", flb_test_azure_blob_managed_identity_system},
    {"managed_identity_user", flb_test_azure_blob_managed_identity_user},
    {"service_principal", flb_test_azure_blob_service_principal},
    {"workload_identity", flb_test_azure_blob_workload_identity},
#endif
    {"shared_key", flb_test_azure_blob_shared_key},
    {"sas_token", flb_test_azure_blob_sas_token},
    {NULL, NULL}
};

#ifdef FLB_HAVE_TLS
/* Test for system-assigned managed identity */
void flb_test_azure_blob_managed_identity_system(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "testaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);
    flb_output_set(ctx, out_ffd, "auto_create_container", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for user-assigned managed identity */
void flb_test_azure_blob_managed_identity_user(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "testaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "00000000-0000-0000-0000-000000000000", NULL);
    flb_output_set(ctx, out_ffd, "auto_create_container", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for service principal authentication */
void flb_test_azure_blob_service_principal(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "testaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "service_principal", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "test-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "test-client-id", NULL);
    flb_output_set(ctx, out_ffd, "client_secret", "test-client-secret", NULL);
    flb_output_set(ctx, out_ffd, "auto_create_container", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for workload identity authentication */
void flb_test_azure_blob_workload_identity(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "testaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "workload_identity", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "test-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "test-client-id", NULL);
    flb_output_set(ctx, out_ffd, "workload_identity_token_file", "/tmp/test-token", NULL);
    flb_output_set(ctx, out_ffd, "auto_create_container", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}
#endif /* FLB_HAVE_TLS */

/* Test for shared key authentication (existing method) */
void flb_test_azure_blob_shared_key(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "testaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "key", NULL);
    flb_output_set(ctx, out_ffd, "shared_key", "dGVzdGtleQ==", NULL);  /* base64 "testkey" */
    flb_output_set(ctx, out_ffd, "auto_create_container", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for SAS token authentication (existing method) */
void flb_test_azure_blob_sas_token(void)
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "testaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "sas", NULL);
    flb_output_set(ctx, out_ffd, "sas_token", "sv=2021-01-01&ss=b&srt=sco&sp=rwdlacx&se=2026-01-01T00:00:00Z&st=2025-01-01T00:00:00Z&spr=https&sig=test", NULL);
    flb_output_set(ctx, out_ffd, "auto_create_container", "off", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}
