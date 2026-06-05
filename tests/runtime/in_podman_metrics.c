/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#define DPATH_PODMAN_REGULAR        FLB_TESTS_DATA_PATH "/data/podman/regular"
#define DPATH_PODMAN_REVERSED       FLB_TESTS_DATA_PATH "/data/podman/reversed"
#define DPATH_PODMAN_NO_CONFIG      FLB_TESTS_DATA_PATH "/data/podman/no_config"
#define DPATH_PODMAN_GARBAGE_CONFIG FLB_TESTS_DATA_PATH "/data/podman/garbage_config"
#define DPATH_PODMAN_NO_SYSFS       FLB_TESTS_DATA_PATH "/data/podman/no_sysfs"
#define DPATH_PODMAN_NO_PROC        FLB_TESTS_DATA_PATH "/data/podman/no_proc"
#define DPATH_PODMAN_GARBAGE        FLB_TESTS_DATA_PATH "/data/podman/garbage"
#define DPATH_PODMAN_CGROUP_V2      FLB_TESTS_DATA_PATH "/data/podman/cgroupv2"


int check_metric(flb_ctx_t *ctx, char *name) {
    struct mk_list *tmp;
    struct mk_list *head;
    struct cfl_list *inner_tmp;
    struct cfl_list *inner_head;

    struct flb_input_instance *i_ins;
    struct cmt_counter *counter;

    int number_of_metrics=0;

    mk_list_foreach_safe(head, tmp, &ctx->config->inputs) {
        i_ins = mk_list_entry(head, struct flb_input_instance, _head);
        cfl_list_foreach_safe(inner_head, inner_tmp, &i_ins->cmt->counters) {
            counter = cfl_list_entry(inner_head, struct cmt_counter, _head);

            if (strlen(name) != 0 && strcmp(name, counter->opts.name) == 0)
            {
                return 0;
            }
            number_of_metrics++;
        }
    }
    return number_of_metrics;

}

void do_create(flb_ctx_t *ctx, char *system, ...)
{
    int in_ffd;
    va_list va;
    char *key;
    char *value;

    in_ffd = flb_input(ctx, (char *) system, NULL);

    va_start(va, system);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);
}

void do_destroy(flb_ctx_t *ctx) {
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_ipm_regular() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_REGULAR "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_REGULAR,
            "path.procfs", DPATH_PODMAN_REGULAR,
            "remove_stale_counters", "true",
            NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "usage_bytes") == 0);
    TEST_CHECK(check_metric(ctx, "receive_bytes_total") == 0);
    do_destroy(ctx);
}

void flb_test_ipm_reversed() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_REVERSED "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_REVERSED,
            "path.procfs", DPATH_PODMAN_REVERSED,
            NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "usage_bytes") == 0);
    TEST_CHECK(check_metric(ctx, "receive_bytes_total") == 0);
    do_destroy(ctx);
}

void flb_test_ipm_garbage_config() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_GARBAGE_CONFIG "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_GARBAGE_CONFIG,
            "path.procfs", DPATH_PODMAN_GARBAGE_CONFIG,
            NULL);
    TEST_CHECK(flb_start(ctx) != 0);
    do_destroy(ctx);
}

void flb_test_ipm_no_config() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_NO_CONFIG "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_NO_CONFIG,
            "path.procfs", DPATH_PODMAN_NO_CONFIG,
            NULL);
    TEST_CHECK(flb_start(ctx) != 0);
    do_destroy(ctx);
}

void flb_test_ipm_no_sysfs() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_NO_SYSFS "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_NO_SYSFS,
            "path.procfs", DPATH_PODMAN_NO_SYSFS,
            NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "usage_bytes") != 0);
    TEST_CHECK(check_metric(ctx, "receive_bytes_total") != 0);
    do_destroy(ctx);
}

void flb_test_ipm_no_proc() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_NO_PROC "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_NO_PROC,
            "path.procfs", DPATH_PODMAN_NO_PROC,
            NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "usage_bytes") == 0);
    TEST_CHECK(check_metric(ctx, "receive_bytes_total") != 0);
    do_destroy(ctx);
}

void flb_test_ipm_garbage() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_GARBAGE "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_GARBAGE,
            "path.procfs", DPATH_PODMAN_GARBAGE,
            NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "usage_bytes") != 0);
    TEST_CHECK(check_metric(ctx, "receive_bytes_total") != 0);
    do_destroy(ctx);
}

void flb_test_ipm_cgroupv2() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
            "podman_metrics",
            "path.config", DPATH_PODMAN_CGROUP_V2 "/config.json",
            "scrape_on_start", "true",
            "path.sysfs", DPATH_PODMAN_CGROUP_V2,
            "path.procfs", DPATH_PODMAN_CGROUP_V2,
            NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "usage_bytes") == 0);
    TEST_CHECK(check_metric(ctx, "receive_bytes_total") == 0);
    do_destroy(ctx);
}

TEST_LIST = {
    {"regular", flb_test_ipm_regular},
    {"reversed", flb_test_ipm_reversed},
    {"no_config", flb_test_ipm_no_config},
    {"garbage_config", flb_test_ipm_garbage_config},
    {"no_sysfs_data", flb_test_ipm_no_sysfs},
    {"no_proc_data", flb_test_ipm_no_proc},
    {"garbage_data", flb_test_ipm_garbage},
    {"cgroup_v2", flb_test_ipm_cgroupv2},
    {NULL, NULL}};
