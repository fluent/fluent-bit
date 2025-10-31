/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_input.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "flb_tests_runtime.h"
#include "../../plugins/in_opentelemetry/opentelemetry.h"
#include "../../plugins/in_opentelemetry/opentelemetry_logs.h"

#define JSON_CONTENT_TYPE "application/json"
#define PORT_OTEL 4318
#define V1_ENDPOINT_LOGS "/v1/logs"
#define MAX_ROUTES 32

/* Route expectation: file path and expected count */
struct route_expectation {
    const char *route_name;
    const char *output_file;
    int expected_count;
};

struct test_ctx {
    flb_ctx_t *flb;
    int i_ffd;
    char output_dir[PATH_MAX];
};

#define TEST_OUTPUT_DIR "otlp_routing_test_output"

/* Construct path to config file in source directory */
static char *get_config_path(const char *config_file)
{
    char path[PATH_MAX];
    char *resolved;
    char *real_resolved;
    char cwd[PATH_MAX];

    /* Try FLB_TESTS_DATA_PATH first (tests/runtime directory) */
    snprintf(path, sizeof(path), "%s/%s", FLB_TESTS_DATA_PATH, config_file);
    if (access(path, R_OK) == 0) {
        resolved = flb_strdup(path);
        return resolved;
    }

    /* Try source root (go up from tests/runtime) */
    snprintf(path, sizeof(path), "%s/../../%s", FLB_TESTS_DATA_PATH, config_file);
    if (access(path, R_OK) == 0) {
        real_resolved = realpath(path, NULL);
        if (real_resolved) {
            resolved = flb_strdup(real_resolved);
            free(real_resolved);
            return resolved;
        }
        resolved = flb_strdup(path);
        return resolved;
    }

    /* Try current working directory */
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        snprintf(path, sizeof(path), "%s/%s", cwd, config_file);
        if (access(path, R_OK) == 0) {
            resolved = flb_strdup(path);
            return resolved;
        }
    }

    /* Return original path as fallback */
    return flb_strdup(config_file);
}

/* Get opentelemetry input instance */
static struct flb_input_instance *get_opentelemetry_instance(flb_ctx_t *flb_ctx)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &flb_ctx->config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (ins->p && strcmp(ins->p->name, "opentelemetry") == 0) {
            return ins;
        }
    }
    return NULL;
}

/* Directly inject JSON payload into opentelemetry plugin */
static int inject_otlp_json(flb_ctx_t *flb_ctx, const char *json_data, size_t json_size)
{
    struct flb_input_instance *ins;
    struct flb_opentelemetry *otel_ctx;
    flb_sds_t content_type;
    flb_sds_t tag;
    int ret;

    /* Get opentelemetry input instance */
    ins = get_opentelemetry_instance(flb_ctx);
    if (!ins || !ins->context) {
        return -1;
    }

    otel_ctx = (struct flb_opentelemetry *)ins->context;

    /* Use default tag if not set */
    if (ins->tag && ins->tag_len > 0) {
        tag = flb_sds_create_len(ins->tag, ins->tag_len);
    }
    else {
        tag = flb_sds_create("opentelemetry.0");
    }

    /* Set content type */
    content_type = flb_sds_create("application/json");

    /* Process logs directly */
    ret = opentelemetry_process_logs(otel_ctx, content_type, tag, flb_sds_len(tag),
                                     (void *)json_data, json_size);

    flb_sds_destroy(content_type);
    flb_sds_destroy(tag);

    return ret;
}

/* Create test context from YAML config file */
static struct test_ctx *test_ctx_create(const char *config_file)
{
    struct test_ctx *ctx;
    char *config_path;
    int ret;
    char cwd[PATH_MAX];

    ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    ctx->flb = flb_create();
    TEST_CHECK(ctx->flb != NULL);

    /* Create output directory */
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        snprintf(ctx->output_dir, sizeof(ctx->output_dir), "%s/%s", cwd, TEST_OUTPUT_DIR);
    }
    else {
        snprintf(ctx->output_dir, sizeof(ctx->output_dir), "./%s", TEST_OUTPUT_DIR);
    }

    /* Create directory if it doesn't exist */
    ret = mkdir(ctx->output_dir, 0755);
    if (ret != 0 && errno != EEXIST) {
        flb_error("[test] Failed to create output directory: %s", ctx->output_dir);
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }


    /* Resolve config file path */
    config_path = get_config_path(config_file);
    TEST_CHECK(config_path != NULL);
    if (!config_path) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    /* Load config from YAML file */
    ret = flb_lib_config_file(ctx->flb, config_path);
    flb_free(config_path);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);

    /* Cleanup output directory (optional - keep for debugging) */
    /* Can uncomment to clean up:
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", ctx->output_dir);
    system(cmd);
    */

    flb_free(ctx);
}

/* Read file content and count JSON records */
static int count_records_in_file(const char *filepath)
{
    FILE *fp;
    char line[8192];
    int count = 0;
    char *trimmed;

    fp = fopen(filepath, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        /* Trim whitespace */
        trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t' || *trimmed == '\n' || *trimmed == '\r') {
            trimmed++;
        }

        /* Skip empty lines */
        if (*trimmed == '\0') {
            continue;
        }

        /* Count lines that contain a timestamp pattern (tag: [timestamp) or JSON object/array */
        /* File output in JSON format writes: "tag: [timestamp, {...}]" */
        /* File output in plain format writes: "{...}" */
        if (strstr(trimmed, ": [") != NULL ||
            *trimmed == '{' ||
            *trimmed == '[') {
            count++;
        }
    }

    fclose(fp);
    return count;
}

/* Remove existing output files before test */
static void cleanup_output_files(struct test_ctx *ctx, struct route_expectation *expectations, int count)
{
    int i;
    char filepath[PATH_MAX];

    for (i = 0; i < count; i++) {
        snprintf(filepath, sizeof(filepath), "%s/%s", ctx->output_dir, expectations[i].output_file);
        unlink(filepath);
    }
}

/* Verify all expectations by reading output files */
static int verify_expectations(struct route_expectation *expectations, int count, struct test_ctx *ctx)
{
    int i;
    int all_passed = 1;
    char filepath[PATH_MAX];
    int actual_count;

    for (i = 0; i < count; i++) {
        struct route_expectation *exp = &expectations[i];

        snprintf(filepath, sizeof(filepath), "%s/%s", ctx->output_dir, exp->output_file);
        actual_count = count_records_in_file(filepath);

        if (actual_count < 0) {
            flb_error("[test] Route '%s': failed to read output file: %s",
                      exp->route_name, filepath);
            all_passed = 0;
        }
        else if (actual_count != exp->expected_count) {
            flb_error("[test] Route '%s': expected %d records, got %d (file: %s)",
                      exp->route_name, exp->expected_count, actual_count, filepath);
            all_passed = 0;
        }
        else {
            flb_info("[test] Route '%s': ✓ %d records (file: %s)",
                     exp->route_name, actual_count, filepath);
        }
    }

    return all_passed;
}

/* Load JSON test data from file */
static flb_sds_t load_json_test_data(const char *filename)
{
    char path[PATH_MAX];
    flb_sds_t content;

    /* Try FLB_TESTS_DATA_PATH first */
    snprintf(path, sizeof(path), "%s/data/opentelemetry/%s", FLB_TESTS_DATA_PATH, filename);
    content = flb_file_read(path);

    /* Try relative to current directory if not found */
    if (!content) {
        snprintf(path, sizeof(path), "data/opentelemetry/%s", filename);
        content = flb_file_read(path);
    }

    return content;
}

/* Main test function */
static void flb_test_otlp_routing(const char *config_file,
                                   const char *json_file,
                                   struct route_expectation *expectations,
                                   int exp_count)
{
    struct test_ctx *ctx;
    flb_sds_t json_content;
    int ret;

    /* Load JSON test data */
    json_content = load_json_test_data(json_file);
    TEST_CHECK(json_content != NULL);
    if (!json_content) {
        return;
    }

    /* Create test context */
    ctx = test_ctx_create(config_file);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        flb_sds_destroy(json_content);
        return;
    }

    /* Clean up any existing output files */
    cleanup_output_files(ctx, expectations, exp_count);

    /* Start Fluent Bit */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Directly inject JSON payload into opentelemetry plugin */
    ret = inject_otlp_json(ctx->flb, json_content, flb_sds_len(json_content));
    TEST_CHECK(ret == 0);

    /* Wait for records to be processed and flushed to files */
    flb_time_msleep(3000);

    /* Verify expectations by reading output files */
    ret = verify_expectations(expectations, exp_count, ctx);
    TEST_CHECK(ret == 1);

    /* Cleanup */
    test_ctx_destroy(ctx);
    flb_sds_destroy(json_content);
}

/* Test case: Comprehensive routing with multiple routes */
void flb_test_otlp_comprehensive_routing()
{
    struct route_expectation expectations[] = {
        {"service_a_logs", "service_a_logs.out", 2},          /* Record 1, Record 2 */
        {"version_2_logs", "version_2_logs.out", 2},          /* Record 3, Record 4 */
        {"production_logs", "production_logs.out", 2},         /* Record 1, Record 2 */
        {"scope_a_logs", "scope_a_logs.out", 2},            /* Record 1, Record 2 */
        {"scope_v2_logs", "scope_v2_logs.out", 1},           /* Record 3 */
        {"backend_component_logs", "backend_component_logs.out", 2},   /* Record 1, Record 2 */
        {"error_body_logs", "error_body_logs.out", 1},         /* Record 2 */
        {"info_level_logs", "info_level_logs.out", 1},         /* Record 1 */
        {"select_operation_logs", "select_operation_logs.out", 1},    /* Record 4 */
        {"default_logs", "default_logs.out", 1},            /* Record 5 */
    };

    /* Config file should be in the same directory as the test */
    flb_test_otlp_routing(
        "otlp_comprehensive_routing_test.yaml",
        "routing_logs.json",
        expectations,
        sizeof(expectations) / sizeof(expectations[0])
    );
}

TEST_LIST = {
    {"otlp_comprehensive_routing", flb_test_otlp_comprehensive_routing},
    {NULL, NULL}
};

