/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ctype.h>
#include <string.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_record_accessor.h>

#include "../../plugins/out_azure_blob/azure_blob.h"
#include "../../plugins/out_azure_blob/azure_blob_uri.h"
#include "../../plugins/out_azure_blob/azure_blob_blockblob.h"
#include "flb_tests_internal.h"

static void ctx_cleanup(struct flb_azure_blob *ctx)
{
    if (ctx->path) {
        flb_sds_destroy(ctx->path);
        ctx->path = NULL;
    }

    if (ctx->base_uri) {
        flb_sds_destroy(ctx->base_uri);
        ctx->base_uri = NULL;
    }

    if (ctx->container_name) {
        flb_sds_destroy(ctx->container_name);
        ctx->container_name = NULL;
    }

    ctx->path_templating_enabled = FLB_FALSE;

    /* Make sure future tests start from a pristine state even if they reuse
     * the same context instance.
     */
    memset(ctx, 0, sizeof(*ctx));
}

static int ctx_init_with_path(struct flb_azure_blob *ctx,
                              const char *path,
                              int templated)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->base_uri = flb_sds_create("https://acct.blob.core.windows.net/");
    ctx->container_name = flb_sds_create("container");
    ctx->path = flb_sds_create(path);
    ctx->path_templating_enabled = templated;

    if (!ctx->base_uri || !ctx->container_name || !ctx->path) {
        ctx_cleanup(ctx);
        return -1;
    }

    return 0;
}

void test_resolve_path_basic_tag(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t resolved = NULL;
    const char *tag = "service.app";
    int ret;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("logs/$TAG");
    TEST_CHECK(ctx.path != NULL);
    if (!ctx.path) {
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    ret = azb_resolve_path(&ctx, tag, (int) strlen(tag), NULL, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);

    if (resolved) {
        TEST_CHECK(strcmp(resolved, "logs/service.app") == 0);
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

void test_resolve_path_custom_delimiter(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t resolved = NULL;
    const char *tag = "prod.backend";
    int ret;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("stream/$TAG[0]/$TAG[1]/$TAG");

    TEST_CHECK(ctx.path != NULL);
    if (!ctx.path) {
        ctx_cleanup(&ctx);
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    ret = azb_resolve_path(&ctx, tag, (int) strlen(tag), NULL, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);

    if (resolved) {
        TEST_CHECK(strcmp(resolved, "stream/prod/backend/prod.backend") == 0);
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

void test_resolve_path_time_tokens(void)
{
    struct flb_azure_blob ctx;
    struct flb_time ts;
    flb_sds_t resolved = NULL;
    const char *expect = "time/2025/11/17/987/987654321/987654321";
    int ret;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("time/%Y/%m/%d/%3N/%9N/%L");
    TEST_CHECK(ctx.path != NULL);
    if (!ctx.path) {
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    flb_time_set(&ts, 1763382896, 987654321);

    ret = azb_resolve_path(&ctx, NULL, 0, &ts, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);

    if (resolved) {
        TEST_CHECK(strcmp(resolved, expect) == 0);
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

void test_resolve_path_uuid_token(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t resolved = NULL;
    int ret;
    size_t i;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("uuid/$UUID");
    TEST_CHECK(ctx.path != NULL);
    if (!ctx.path) {
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    ret = azb_resolve_path(&ctx, "demo", 4, NULL, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);

    if (resolved) {
        const char *suffix;

        TEST_CHECK(strncmp(resolved, "uuid/", 5) == 0);

        suffix = resolved + 5;
        TEST_CHECK(strlen(suffix) == 8);
        TEST_CHECK(strstr(resolved, "$UUID") == NULL);

        for (i = 0; i < 8 && suffix[i] != '\0'; i++) {
            TEST_CHECK(isalnum((unsigned char) suffix[i]) != 0);
        }

        TEST_CHECK(i == 8 && suffix[8] == '\0');
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

void test_resolve_path_multiple_uuid_tokens(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t resolved = NULL;
    int ret;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("multi/$UUID/data/$UUID");
    TEST_CHECK(ctx.path != NULL);
    if (!ctx.path) {
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    ret = azb_resolve_path(&ctx, "demo", 4, NULL, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);

    if (resolved) {
        const char *first_start;
        const char *second_marker;
        const char *second_start;

        first_start = resolved + strlen("multi/");
        second_marker = strstr(first_start, "/data/");
        TEST_CHECK(second_marker != NULL);

        if (second_marker != NULL) {
            size_t first_len;
            size_t second_len;

            first_len = (size_t)(second_marker - first_start);
            TEST_CHECK(first_len == 8);

            second_start = second_marker + strlen("/data/");
            second_len = strlen(second_start);
            TEST_CHECK(second_len == 8);

            if (first_len == 8 && second_len == 8) {
                TEST_CHECK(strncmp(first_start, second_start, 8) == 0);
            }
        }

        TEST_CHECK(strstr(resolved, "$UUID") == NULL);
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

void test_resolve_path_empty_result(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t resolved = NULL;
    int ret;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("$TAG[5]");
    TEST_CHECK(ctx.path != NULL);
    if (!ctx.path) {
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    ret = azb_resolve_path(&ctx, "a.b", 3, NULL, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);
    if (resolved) {
        TEST_CHECK(flb_sds_len(resolved) == 0);
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

void test_resolve_path_empty_prefix_uri(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t resolved = NULL;
    flb_sds_t uri = NULL;
    int ret;

    memset(&ctx, 0, sizeof(ctx));

    ctx.base_uri = flb_sds_create("https://acct.blob.core.windows.net/");
    ctx.container_name = flb_sds_create("container");
    ctx.path = flb_sds_create("$TAG[5]");

    TEST_CHECK(ctx.base_uri != NULL);
    TEST_CHECK(ctx.container_name != NULL);
    TEST_CHECK(ctx.path != NULL);
    if (!ctx.base_uri || !ctx.container_name || !ctx.path) {
        ctx_cleanup(&ctx);
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    ret = azb_resolve_path(&ctx, "a.b", 3, NULL, &resolved);
    TEST_CHECK(ret == 0);
    TEST_CHECK(resolved != NULL);
    if (!resolved) {
        ctx_cleanup(&ctx);
        return;
    }

    uri = azb_uri_create_blob(&ctx, resolved, "file.log");
    TEST_CHECK(uri != NULL);

    if (uri) {
        TEST_CHECK(strcmp(uri,
                          "https://acct.blob.core.windows.net/container/file.log") == 0);
        flb_sds_destroy(uri);
    }

    flb_sds_destroy(resolved);

    ctx_cleanup(&ctx);
}

void test_blocklist_uri_requires_resolved_prefix(void)
{
    struct flb_azure_blob ctx;
    struct flb_time ts_first;
    struct flb_time ts_second;
    flb_sds_t prefix_first = NULL;
    flb_sds_t prefix_second = NULL;
    flb_sds_t uri_upload = NULL;
    flb_sds_t uri_wrong = NULL;
    flb_sds_t uri_correct = NULL;
    int ret;
    const char *tag = "service.app";
    const char *block_id = "Zmx1ZW50LWJsb2NrLWlk";
    const char *random_id = "RANDOMID";

    ret = ctx_init_with_path(&ctx, "logs/%S/$UUID", FLB_TRUE);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    flb_time_set(&ts_first, 100, 0);
    flb_time_set(&ts_second, 200, 0);

    ret = azb_resolve_path(&ctx, tag, (int) strlen(tag), &ts_first, &prefix_first);
    TEST_CHECK(ret == 0 && prefix_first != NULL);

    ret = azb_resolve_path(&ctx, tag, (int) strlen(tag), &ts_second, &prefix_second);
    TEST_CHECK(ret == 0 && prefix_second != NULL);

    if (!(prefix_first && prefix_second)) {
        goto cleanup;
    }

    TEST_CHECK(strcmp(prefix_first, prefix_second) != 0);

    uri_upload = azb_block_blob_uri(&ctx, prefix_first, "blob.log",
                                    (char *) block_id, 0, (char *) random_id);
    TEST_CHECK(uri_upload != NULL);
    if (uri_upload) {
        TEST_CHECK(strstr(uri_upload, prefix_first) != NULL);
    }

    uri_wrong = azb_block_blob_blocklist_uri(&ctx, ctx.path, "blob.log");
    TEST_CHECK(uri_wrong != NULL);
    if (uri_wrong) {
        TEST_CHECK(strstr(uri_wrong, "%S") != NULL);
    }

    uri_correct = azb_block_blob_blocklist_uri(&ctx, prefix_first, "blob.log");
    TEST_CHECK(uri_correct != NULL);
    if (uri_correct) {
        TEST_CHECK(strstr(uri_correct, prefix_first) != NULL);
    }

cleanup:
    if (prefix_first) {
        flb_sds_destroy(prefix_first);
    }
    if (prefix_second) {
        flb_sds_destroy(prefix_second);
    }
    if (uri_upload) {
        flb_sds_destroy(uri_upload);
    }
    if (uri_wrong) {
        flb_sds_destroy(uri_wrong);
    }
    if (uri_correct) {
        flb_sds_destroy(uri_correct);
    }

    ctx_cleanup(&ctx);
}

void test_blocklist_uri_legacy_prefix_fallback(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t uri;
    int ret;

    ret = ctx_init_with_path(&ctx, "static/prefix", FLB_FALSE);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    uri = azb_block_blob_blocklist_uri(&ctx, NULL, "file.log");
    TEST_CHECK(uri != NULL);
    if (uri) {
        TEST_CHECK(strstr(uri, "static/prefix/file.log") != NULL);
        flb_sds_destroy(uri);
    }

    ctx_cleanup(&ctx);
}

void test_commit_prefix_fallback_static_path(void)
{
    struct flb_azure_blob ctx;
    const char *prefix;

    memset(&ctx, 0, sizeof(ctx));

    ctx.path = flb_sds_create("static/prefix");
    TEST_CHECK(ctx.path != NULL);
    if (ctx.path == NULL) {
        return;
    }

    ctx.path_templating_enabled = FLB_TRUE;

    prefix = azb_commit_prefix_with_fallback(&ctx, NULL);
    TEST_CHECK(prefix == ctx.path);

    ctx_cleanup(&ctx);
}

void test_uri_create_static_prefix_fallback(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t uri;
    int ret;

    ret = ctx_init_with_path(&ctx, "static/prefix", FLB_TRUE);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    uri = azb_uri_create_blob(&ctx, NULL, "file.log");
    TEST_CHECK(uri != NULL);
    if (uri != NULL) {
        TEST_CHECK(strstr(uri, "static/prefix/file.log") != NULL);
        flb_sds_destroy(uri);
    }

    ctx_cleanup(&ctx);
}

void test_block_blob_commit_requires_suffix(void)
{
    struct flb_azure_blob ctx;
    flb_sds_t uri;
    int ret;

    ret = ctx_init_with_path(&ctx, "logs/%Y/%m/%d", FLB_TRUE);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    uri = azb_block_blob_uri_commit(&ctx, NULL, "blob.log", 1234, "RANDOM");
    TEST_CHECK(uri != NULL);
    if (uri) {
        TEST_CHECK(strstr(uri, "RANDOM") != NULL);
        flb_sds_destroy(uri);
    }

    uri = azb_block_blob_uri_commit(&ctx, NULL, "blob.log", 1234, NULL);
    TEST_CHECK(uri == NULL);

    ctx_cleanup(&ctx);
}

TEST_LIST = {
    {"resolve_path_basic_tag", test_resolve_path_basic_tag},
    {"resolve_path_custom_delimiter", test_resolve_path_custom_delimiter},
    {"resolve_path_time_tokens", test_resolve_path_time_tokens},
    {"resolve_path_uuid_token", test_resolve_path_uuid_token},
    {"resolve_path_multiple_uuid_tokens", test_resolve_path_multiple_uuid_tokens},
    {"resolve_path_empty_result", test_resolve_path_empty_result},
    {"resolve_path_empty_prefix_uri", test_resolve_path_empty_prefix_uri},
    {"blocklist_uri_requires_resolved_prefix", test_blocklist_uri_requires_resolved_prefix},
    {"blocklist_uri_legacy_prefix_fallback", test_blocklist_uri_legacy_prefix_fallback},
    {"commit_prefix_fallback_static_path", test_commit_prefix_fallback_static_path},
    {"uri_create_static_prefix_fallback", test_uri_create_static_prefix_fallback},
    {"block_blob_commit_requires_suffix", test_block_blob_commit_requires_suffix},
    {0}
};
