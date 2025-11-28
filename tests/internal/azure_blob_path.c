/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ctype.h>
#include <string.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_record_accessor.h>

#include "../../plugins/out_azure_blob/azure_blob.h"
#include "flb_tests_internal.h"

static void ctx_cleanup(struct flb_azure_blob *ctx)
{
    if (ctx->path) {
        flb_sds_destroy(ctx->path);
        ctx->path = NULL;
    }

    ctx->path_templating_enabled = FLB_FALSE;
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
    TEST_CHECK(resolved == NULL);

    if (resolved) {
        flb_sds_destroy(resolved);
    }

    ctx_cleanup(&ctx);
}

TEST_LIST = {
    {"resolve_path_basic_tag", test_resolve_path_basic_tag},
    {"resolve_path_custom_delimiter", test_resolve_path_custom_delimiter},
    {"resolve_path_time_tokens", test_resolve_path_time_tokens},
    {"resolve_path_uuid_token", test_resolve_path_uuid_token},
    {"resolve_path_multiple_uuid_tokens", test_resolve_path_multiple_uuid_tokens},
    {"resolve_path_empty_result", test_resolve_path_empty_result},
    {0}
};
