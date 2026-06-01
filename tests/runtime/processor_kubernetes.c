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
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

#include <string.h>
#include <unistd.h>

#ifdef _WIN32
    #define TIME_EPSILON_MS 30
#else
    #define TIME_EPSILON_MS 10
#endif

#define KUBE_IP          "127.0.0.1"
#define KUBE_PORT        "8002"
#define KUBE_URL         "http://" KUBE_IP ":" KUBE_PORT
#define DPATH            FLB_TESTS_DATA_PATH "/data/kubernetes"

struct processor_kube_result {
    int matched;
};

static void wait_with_timeout(uint32_t timeout_ms,
                              struct processor_kube_result *result)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;

    flb_time_get(&start_time);

    while (result->matched == 0) {
        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms - TIME_EPSILON_MS) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            break;
        }
    }
}

static int cb_check_result(void *record, size_t size, void *data)
{
    char *out;
    struct processor_kube_result *result;

    (void) size;

    out = (char *) record;
    result = data;

    TEST_CHECK_(strstr(out, "\"stream\":\"stdout\"") != NULL,
                "record has stream field");
    TEST_CHECK_(strstr(out, "\"text\":\"Simple text\"") != NULL,
                "processor merged JSON log content");
    TEST_CHECK_(strstr(out, "\"kubernetes\":") != NULL,
                "processor appended Kubernetes metadata");
    TEST_CHECK_(strstr(out, "\"pod_name\":\"keep-log-disabled\"") != NULL,
                "processor set pod_name");
    TEST_CHECK_(strstr(out, "\"namespace_name\":\"options\"") != NULL,
                "processor set namespace_name");
    TEST_CHECK_(strstr(out, "\"container_name\":\"json\"") != NULL,
                "processor set container_name");
    TEST_CHECK_(strstr(out, "\"log\":") == NULL,
                "processor removed original log field");

    result->matched++;
    flb_free(record);

    return 0;
}

static int set_processor_property(struct flb_processor_unit *pu,
                                  const char *key, const char *value)
{
    int ret;

    ret = flb_processor_unit_set_property_str(pu, key, value);
    TEST_CHECK_(ret == 0, "setting processor property %s", key);

    return ret;
}

static void flb_test_processor_kubernetes_merge_log()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *flb = NULL;
    struct flb_processor *proc = NULL;
    struct flb_processor_unit *pu;
    struct flb_lib_out_cb cb_data;
    struct processor_kube_result result = {0};

    flb = flb_create();
    TEST_CHECK_(flb != NULL, "initialising service");
    if (flb == NULL) {
        return;
    }

    ret = flb_service_set(flb,
                          "Flush", "1",
                          "Grace", "1",
                          "Log_Level", "error",
                          "Parsers_File", DPATH "/parsers.conf",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(flb, "tail", NULL);
    TEST_CHECK_(in_ffd >= 0, "initialising input");
    if (in_ffd < 0) {
        goto exit;
    }

    ret = flb_input_set(flb, in_ffd,
                        "Tag", "kube.<namespace>.<pod>.<container>",
                        "Tag_Regex", "^" DPATH "/log/(?:[^/]+/)?"
                                     "(?<namespace>.+)_(?<pod>.+)_"
                                     "(?<container>.+)\\.log$",
                        "Path", DPATH "/log/options/options_keep-log-disabled_json.log",
                        "Parser", "docker",
                        "Docker_Mode", "On",
                        "read_from_head", "on",
                        NULL);
    TEST_CHECK_(ret == 0, "setting input options");

    proc = flb_processor_create(flb->config, "unit_test", NULL, 0);
    TEST_CHECK_(proc != NULL, "creating processor");
    if (proc == NULL) {
        goto exit;
    }

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "kubernetes");
    TEST_CHECK_(pu != NULL, "creating kubernetes processor unit");
    if (pu == NULL) {
        goto exit;
    }

    ret = set_processor_property(pu, "kube_url", KUBE_URL);
    if (ret != 0) {
        goto exit;
    }
    ret = set_processor_property(pu, "kube_meta_preload_cache_dir",
                                 DPATH "/meta");
    if (ret != 0) {
        goto exit;
    }
    ret = set_processor_property(pu, "regex_parser", "kubernetes-tag");
    if (ret != 0) {
        goto exit;
    }
    ret = set_processor_property(pu, "kube_tag_prefix", "kube.");
    if (ret != 0) {
        goto exit;
    }
    ret = set_processor_property(pu, "merge_log", "On");
    if (ret != 0) {
        goto exit;
    }
    ret = set_processor_property(pu, "keep_log", "Off");
    if (ret != 0) {
        goto exit;
    }

    ret = flb_input_set_processor(flb, in_ffd, proc);
    TEST_CHECK_(ret == 0, "attaching processor to input");

    cb_data.cb = cb_check_result;
    cb_data.data = &result;

    out_ffd = flb_output(flb, "lib", (void *) &cb_data);
    TEST_CHECK_(out_ffd >= 0, "initialising output");
    if (out_ffd < 0) {
        goto exit;
    }

    ret = flb_output_set(flb, out_ffd,
                         "Match", "kube.*",
                         "format", "json",
                         NULL);
    TEST_CHECK_(ret == 0, "setting output options");

    ret = flb_start(flb);
    TEST_CHECK_(ret == 0, "starting engine");
    if (ret != 0) {
        goto exit;
    }

    wait_with_timeout(5000, &result);
    TEST_CHECK_(result.matched == 1, "one processed record was emitted");

    ret = flb_stop(flb);
    TEST_CHECK_(ret == 0, "stopping engine");

exit:
    if (flb != NULL) {
        flb_destroy(flb);
    }
}

TEST_LIST = {
    {"processor_kubernetes.merge_log", flb_test_processor_kubernetes_merge_log },
    {NULL, NULL}
};
