/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023 The Fluent Bit Authors
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

#define DPATH_DOCKER_SYSFS_CGROUPV1     FLB_TESTS_DATA_PATH "/data/docker/cgroupv1"
#define DPATH_DOCKER_CONTAINER_CGROUPV1 FLB_TESTS_DATA_PATH "/data/docker/cgroupv1/var/lib/containers"
#define DPATH_DOCKER_SYSFS_CGROUPV2     FLB_TESTS_DATA_PATH "/data/docker/cgroupv2"
#define DPATH_DOCKER_CONTAINER_CGROUPV2 FLB_TESTS_DATA_PATH "/data/docker/cgroupv2/var/lib/containers"

int check_metric(flb_ctx_t *ctx, char *name) {
    struct mk_list *tmp;
    struct mk_list *head;
    struct cfl_list *inner_tmp;
    struct cfl_list *inner_head;

    struct flb_input_instance *i_ins;
    struct cmt_counter *counter;

    int number_of_metrics = 0;

    mk_list_foreach_safe(head, tmp, &ctx->config->inputs) {
        i_ins = mk_list_entry(head, struct flb_input_instance, _head);
        cfl_list_foreach_safe(inner_head, inner_tmp, &i_ins->cmt->counters) {
            counter = cfl_list_entry(inner_head, struct cmt_counter, _head);

            if (strlen(name) != 0 && strcmp(name, counter->opts.name) == 0) {
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
    int out_ffd;
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

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);
}

void do_destroy(flb_ctx_t *ctx) {
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_in_docker_cgroupv1() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
              "docker",
              "path.sysfs",      DPATH_DOCKER_SYSFS_CGROUPV1,
              "path.containers", DPATH_DOCKER_CONTAINER_CGROUPV1,
              NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "cpu_used") != 0);
    TEST_CHECK(check_metric(ctx, "mem_used") != 0);
    TEST_CHECK(check_metric(ctx, "mem_limit") != 0);
    do_destroy(ctx);
}

void flb_test_in_docker_cgroupv2() {
    flb_ctx_t *ctx = flb_create();
    do_create(ctx,
              "docker",
              "path.sysfs",      DPATH_DOCKER_SYSFS_CGROUPV2,
              "path.containers", DPATH_DOCKER_CONTAINER_CGROUPV2,
              NULL);
    TEST_CHECK(flb_start(ctx) == 0);
    sleep(1);
    TEST_CHECK(check_metric(ctx, "cpu_used") != 0);
    TEST_CHECK(check_metric(ctx, "mem_used") != 0);
    TEST_CHECK(check_metric(ctx, "mem_limit") != 0);
    do_destroy(ctx);
}

TEST_LIST = {
    {"cgroup_v1", flb_test_in_docker_cgroupv1},
    {"cgroup_v2", flb_test_in_docker_cgroupv2},
    {NULL, NULL}};
