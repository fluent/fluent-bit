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

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_compression.h>

#include "flb_tests_internal.h"

#include "../../plugins/out_azure_blob/azure_blob.h"
#include "../../plugins/out_azure_blob/azure_blob_blockblob.h"
#include "../../plugins/out_azure_blob/azure_blob_http.h"

struct azure_blob_fixture {
    struct flb_config *config;
    struct flb_upstream *upstream;
    struct flb_connection *connection;
};

static int azure_blob_fixture_init(struct azure_blob_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));

    fixture->config = flb_config_init();
    if (!TEST_CHECK(fixture->config != NULL)) {
        TEST_MSG("flb_config_init failed");
        return -1;
    }

    fixture->upstream = flb_upstream_create(fixture->config, "127.0.0.1",
                                            80, FLB_IO_TCP, NULL);
    if (!TEST_CHECK(fixture->upstream != NULL)) {
        TEST_MSG("flb_upstream_create failed");
        flb_config_exit(fixture->config);
        fixture->config = NULL;
        return -1;
    }

    fixture->connection = flb_calloc(1, sizeof(struct flb_connection));
    if (!TEST_CHECK(fixture->connection != NULL)) {
        flb_errno();
        TEST_MSG("flb_calloc(flb_connection) failed");
        flb_upstream_destroy(fixture->upstream);
        fixture->upstream = NULL;
        flb_config_exit(fixture->config);
        fixture->config = NULL;
        return -1;
    }

    fixture->connection->upstream = fixture->upstream;
    return 0;
}

static void azure_blob_fixture_destroy(struct azure_blob_fixture *fixture)
{
    if (fixture->connection != NULL) {
        flb_free(fixture->connection);
    }

    if (fixture->upstream != NULL) {
        flb_upstream_destroy(fixture->upstream);
    }

    if (fixture->config != NULL) {
        flb_config_exit(fixture->config);
    }
}

static void azure_blob_ctx_init(struct flb_azure_blob *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->base_uri = flb_sds_create("/");
    ctx->container_name = flb_sds_create("container");
    ctx->btype = AZURE_BLOB_BLOCKBLOB;
    ctx->atype = AZURE_BLOB_AUTH_KEY;
}

static void azure_blob_ctx_destroy(struct flb_azure_blob *ctx)
{
    if (ctx->base_uri != NULL) {
        flb_sds_destroy(ctx->base_uri);
    }

    if (ctx->container_name != NULL) {
        flb_sds_destroy(ctx->container_name);
    }
}

static void test_block_blob_extension_zstd()
{
    struct flb_azure_blob ctx;
    flb_sds_t uri;

    azure_blob_ctx_init(&ctx);
    ctx.compress_blob = FLB_TRUE;
    ctx.compression = FLB_COMPRESSION_ALGORITHM_ZSTD;

    uri = azb_block_blob_uri(&ctx, "file", "block", 123, "rand");
    TEST_CHECK(uri != NULL);
    TEST_CHECK(strstr(uri, ".zst?blockid=") != NULL);

    flb_sds_destroy(uri);
    azure_blob_ctx_destroy(&ctx);
}

static void test_block_blob_extension_gzip_default()
{
    struct flb_azure_blob ctx;
    flb_sds_t uri;

    azure_blob_ctx_init(&ctx);
    ctx.compress_blob = FLB_TRUE;
    ctx.compression = FLB_COMPRESSION_ALGORITHM_NONE;

    /* When no explicit algorithm is configured, gzip remains the
     * fallback to preserve legacy behavior. */

    uri = azb_block_blob_uri(&ctx, "file", "block", 123, "rand");
    TEST_CHECK(uri != NULL);
    TEST_CHECK(strstr(uri, ".gz?blockid=") != NULL);

    flb_sds_destroy(uri);
    azure_blob_ctx_destroy(&ctx);
}

static void test_block_blob_extension_disabled()
{
    struct flb_azure_blob ctx;
    flb_sds_t uri;

    azure_blob_ctx_init(&ctx);
    ctx.compress_blob = FLB_FALSE;
    ctx.compression = FLB_COMPRESSION_ALGORITHM_ZSTD;

    uri = azb_block_blob_uri(&ctx, "file", "block", 123, "rand");
    TEST_CHECK(uri != NULL);
    TEST_CHECK(strstr(uri, ".gz?blockid=") == NULL);
    TEST_CHECK(strstr(uri, ".zst?blockid=") == NULL);

    flb_sds_destroy(uri);
    azure_blob_ctx_destroy(&ctx);
}

static void test_http_headers_zstd_encoding()
{
    struct azure_blob_fixture fixture;
    struct flb_http_client *client;
    struct flb_azure_blob ctx;
    struct flb_output_instance ins;
    flb_sds_t header;
    int ret;

    ret = azure_blob_fixture_init(&fixture);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    client = flb_http_client(fixture.connection, FLB_HTTP_PUT, "/resource",
                              NULL, 0, "localhost", 80, NULL, 0);
    TEST_CHECK(client != NULL);
    if (client == NULL) {
        azure_blob_fixture_destroy(&fixture);
        return;
    }

    memset(&ins, 0, sizeof(ins));
    azure_blob_ctx_init(&ctx);
    ctx.ins = &ins;
    ctx.atype = AZURE_BLOB_AUTH_SAS;

    ret = azb_http_client_setup(&ctx, client, 1, FLB_FALSE,
                                AZURE_BLOB_CT_JSON,
                                AZURE_BLOB_CE_ZSTD);
    TEST_CHECK(ret == 0);

    header = flb_http_get_header(client, "Content-Encoding", 16);
    TEST_CHECK(header != NULL);
    if (header != NULL) {
        TEST_CHECK(strcmp(header, "zstd") == 0);
        flb_sds_destroy(header);
    }

    header = flb_http_get_header(client, "Content-Type", 12);
    TEST_CHECK(header != NULL);
    if (header != NULL) {
        TEST_CHECK(strcmp(header, "application/json") == 0);
        flb_sds_destroy(header);
    }

    flb_http_client_destroy(client);
    azure_blob_ctx_destroy(&ctx);
    azure_blob_fixture_destroy(&fixture);
}

static void test_http_headers_zstd_content_type()
{
    struct azure_blob_fixture fixture;
    struct flb_http_client *client;
    struct flb_azure_blob ctx;
    struct flb_output_instance ins;
    flb_sds_t header;
    int ret;

    ret = azure_blob_fixture_init(&fixture);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    client = flb_http_client(fixture.connection, FLB_HTTP_PUT, "/resource",
                              NULL, 0, "localhost", 80, NULL, 0);
    TEST_CHECK(client != NULL);
    if (client == NULL) {
        azure_blob_fixture_destroy(&fixture);
        return;
    }

    memset(&ins, 0, sizeof(ins));
    azure_blob_ctx_init(&ctx);
    ctx.ins = &ins;
    ctx.atype = AZURE_BLOB_AUTH_SAS;

    ret = azb_http_client_setup(&ctx, client, 1, FLB_FALSE,
                                AZURE_BLOB_CT_ZSTD,
                                AZURE_BLOB_CE_NONE);
    TEST_CHECK(ret == 0);

    header = flb_http_get_header(client, "Content-Type", 12);
    TEST_CHECK(header != NULL);
    if (header != NULL) {
        TEST_CHECK(strcmp(header, "application/zstd") == 0);
        flb_sds_destroy(header);
    }

    flb_http_client_destroy(client);
    azure_blob_ctx_destroy(&ctx);
    azure_blob_fixture_destroy(&fixture);
}

TEST_LIST = {
    {"block_blob_extension_zstd", test_block_blob_extension_zstd},
    {"block_blob_extension_gzip_default", test_block_blob_extension_gzip_default},
    {"block_blob_extension_disabled", test_block_blob_extension_disabled},
    {"http_headers_zstd_encoding", test_http_headers_zstd_encoding},
    {"http_headers_zstd_content_type", test_http_headers_zstd_content_type},
    { 0 }
};
