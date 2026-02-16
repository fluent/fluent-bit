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

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */

/* Test functions */
void flb_test_azure_blob_json_invalid(void);
void flb_test_azure_blob_managed_identity_system(void);
void flb_test_azure_blob_managed_identity_user(void);
void flb_test_azure_blob_workload_identity(void);
void flb_test_azure_blob_mi_missing_client_id(void);
void flb_test_azure_blob_wi_missing_tenant_id(void);
void flb_test_azure_blob_wi_missing_client_id(void);
void flb_test_azure_blob_invalid_auth_type(void);
void flb_test_azure_blob_key_auth(void);
void flb_test_azure_blob_sas_auth(void);

/* Test list */
TEST_LIST = {
    {"json_invalid",                flb_test_azure_blob_json_invalid},
    {"managed_identity_system",     flb_test_azure_blob_managed_identity_system},
    {"managed_identity_user",       flb_test_azure_blob_managed_identity_user},
    {"workload_identity",           flb_test_azure_blob_workload_identity},
    {"mi_missing_client_id",        flb_test_azure_blob_mi_missing_client_id},
    {"wi_missing_tenant_id",        flb_test_azure_blob_wi_missing_tenant_id},
    {"wi_missing_client_id",        flb_test_azure_blob_wi_missing_client_id},
    {"invalid_auth_type",           flb_test_azure_blob_invalid_auth_type},
    {"key_auth",                    flb_test_azure_blob_key_auth},
    {"sas_auth",                    flb_test_azure_blob_sas_auth},
    {NULL, NULL}
};

void flb_test_azure_blob_json_invalid(void)
{
    int i;
    int ret;
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

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "key", NULL);
    flb_output_set(ctx, out_ffd,
                   "shared_key",
                   "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsu"
                   "Fq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1);

    flb_stop(ctx);
    flb_destroy(ctx);
}

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
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "system", NULL);

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
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id",
                   "00000000-0000-0000-0000-000000000000", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test for workload identity */
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
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "workload_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "my-client-id", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "my-tenant-id", NULL);
    flb_output_set(ctx, out_ffd, "workload_identity_token_file",
                   "/path/to/token/file", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Error: managed_identity without client_id should fail init */
void flb_test_azure_blob_mi_missing_client_id(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "managed_identity", NULL);
    /* client_id intentionally omitted */

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Error: workload_identity without tenant_id should fail init */
void flb_test_azure_blob_wi_missing_tenant_id(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "workload_identity", NULL);
    flb_output_set(ctx, out_ffd, "client_id", "my-client-id", NULL);
    /* tenant_id intentionally omitted */

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Error: workload_identity without client_id should fail init */
void flb_test_azure_blob_wi_missing_client_id(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "workload_identity", NULL);
    flb_output_set(ctx, out_ffd, "tenant_id", "my-tenant-id", NULL);
    /* client_id intentionally omitted */

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Error: invalid auth_type should fail init */
void flb_test_azure_blob_invalid_auth_type(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "azure_blob", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "bogus_type", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test existing key auth still works */
void flb_test_azure_blob_key_auth(void)
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
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "key", NULL);
    flb_output_set(ctx, out_ffd,
                   "shared_key",
                   "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsu"
                   "Fq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test existing SAS auth still works */
void flb_test_azure_blob_sas_auth(void)
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
    flb_output_set(ctx, out_ffd, "account_name", "devaccount", NULL);
    flb_output_set(ctx, out_ffd, "container_name", "testcontainer", NULL);
    flb_output_set(ctx, out_ffd, "auth_type", "sas", NULL);
    flb_output_set(ctx, out_ffd, "sas_token",
                   "?sv=2019-12-12&ss=b&srt=sco&sp=rwdlacx"
                   "&se=2030-01-01T00:00:00Z&st=2020-01-01T00:00:00Z"
                   "&spr=https&sig=fakesig", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}
