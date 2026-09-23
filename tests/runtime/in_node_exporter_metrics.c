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

#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_text.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "flb_tests_runtime.h"

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int output_count;

static int cb_count_output(void *record, size_t size, void *data)
{
    (void) size;
    (void) data;

    pthread_mutex_lock(&result_mutex);
    output_count++;
    pthread_mutex_unlock(&result_mutex);

    flb_free(record);

    return 0;
}

static int get_output_count(void)
{
    int count;

    pthread_mutex_lock(&result_mutex);
    count = output_count;
    pthread_mutex_unlock(&result_mutex);

    return count;
}

static void test_diskstats(void)
{
    int ret;
    int input_fd;
    int output_fd;
    int count;
    uint64_t elapsed_ms;
    flb_ctx_t *ctx;
    struct flb_time start;
    struct flb_time end;
    struct flb_time diff;
    struct flb_lib_out_cb callback;

    output_count = 0;
    elapsed_ms = 0;
    callback.cb = cb_count_output;
    callback.data = NULL;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    ret = flb_service_set(ctx,
                          "Flush", "0.2",
                          "Grace", "1",
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK(ret == 0);

    input_fd = flb_input(ctx, (char *) "node_exporter_metrics", NULL);
    TEST_CHECK(input_fd >= 0);

    ret = flb_input_set(ctx, input_fd,
                        "metrics", "diskstats",
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    output_fd = flb_output(ctx, (char *) "lib", &callback);
    TEST_CHECK(output_fd >= 0);

    ret = flb_output_set(ctx, output_fd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_get(&start);
    count = get_output_count();
    while (count == 0 && elapsed_ms < 5000) {
        flb_time_msleep(100);
        count = get_output_count();
        flb_time_get(&end);
        flb_time_diff(&end, &start, &diff);
        elapsed_ms = flb_time_to_nanosec(&diff) / 1000000;
    }

    TEST_CHECK(count > 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

#ifdef FLB_SYSTEM_LINUX

#define NETDEV_HEADER                                                        \
    "Inter-|   Receive                                                |"     \
    "  Transmit\n"                                                        \
    " face |bytes    packets errs drop fifo frame compressed multicast|"   \
    "bytes    packets errs drop fifo colls carrier compressed\n"

static int stale_device_observed;
static int stale_device_removed;
static int clean_snapshot_observed;

static int write_netdev_file(const char *path, int include_stale_device)
{
    int ret;
    FILE *stream;

    stream = fopen(path, "w");
    if (stream == NULL) {
        return -1;
    }

    ret = fprintf(stream,
                  NETDEV_HEADER
                  "  eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n");
    if (ret >= 0 && include_stale_device) {
        ret = fprintf(stream,
                      "  veth-stale: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n");
    }

    if (fclose(stream) != 0) {
        return -1;
    }

    return ret < 0 ? -1 : 0;
}

static int cb_check_metrics(void *record, size_t size, void *data)
{
    int ret;
    int removed;
    size_t offset;
    cfl_sds_t text;
    struct cmt *cmt;

    (void) data;

    offset = 0;
    cmt = NULL;
    ret = cmt_decode_msgpack_create(&cmt, (char *) record, size, &offset);
    if (ret == 0) {
        text = cmt_encode_text_create(cmt);
        if (text != NULL) {
            pthread_mutex_lock(&result_mutex);
            removed = stale_device_removed;
            if (!removed && strstr(text, "device=\"veth-stale\"") != NULL) {
                stale_device_observed = FLB_TRUE;
            }
            else if (removed && strstr(text, "device=\"eth0\"") != NULL &&
                     strstr(text, "device=\"veth-stale\"") == NULL) {
                clean_snapshot_observed = FLB_TRUE;
            }
            pthread_mutex_unlock(&result_mutex);
            cmt_encode_text_destroy(text);
        }
        cmt_destroy(cmt);
    }

    flb_free(record);
    return 0;
}

static int wait_for_flag(int *flag, int timeout_ms)
{
    int elapsed;
    int value;

    elapsed = 0;
    while (elapsed < timeout_ms) {
        pthread_mutex_lock(&result_mutex);
        value = *flag;
        pthread_mutex_unlock(&result_mutex);

        if (value == FLB_TRUE) {
            return 0;
        }

        flb_time_msleep(100);
        elapsed += 100;
    }

    return -1;
}

static void test_netdev_removes_stale_devices(void)
{
    int ret;
    int input_fd;
    int output_fd;
    char procfs_template[] = "/tmp/flb-node-exporter-XXXXXX";
    char net_path[sizeof(procfs_template) + 5];
    char netdev_path[sizeof(procfs_template) + 9];
    char *procfs_path;
    flb_ctx_t *flb;
    struct flb_lib_out_cb callback;

    procfs_path = mkdtemp(procfs_template);
    TEST_CHECK(procfs_path != NULL);
    if (procfs_path == NULL) {
        return;
    }

    snprintf(net_path, sizeof(net_path), "%s/net", procfs_path);
    snprintf(netdev_path, sizeof(netdev_path), "%s/net/dev", procfs_path);
    ret = mkdir(net_path, 0700);
    TEST_CHECK(ret == 0);
    ret = write_netdev_file(netdev_path, FLB_TRUE);
    TEST_CHECK(ret == 0);

    pthread_mutex_lock(&result_mutex);
    stale_device_observed = FLB_FALSE;
    stale_device_removed = FLB_FALSE;
    clean_snapshot_observed = FLB_FALSE;
    pthread_mutex_unlock(&result_mutex);

    memset(&callback, 0, sizeof(callback));
    callback.cb = cb_check_metrics;

    flb = flb_create();
    TEST_CHECK(flb != NULL);
    if (flb == NULL) {
        goto cleanup;
    }

    ret = flb_service_set(flb,
                          "Flush", "0.2",
                          "Grace", "1",
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK(ret == 0);

    input_fd = flb_input(flb, (char *) "node_exporter_metrics", NULL);
    TEST_CHECK(input_fd >= 0);
    ret = flb_input_set(flb, input_fd,
                        "metrics", "netdev",
                        "path.procfs", procfs_path,
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    output_fd = flb_output(flb, (char *) "lib", &callback);
    TEST_CHECK(output_fd >= 0);
    ret = flb_output_set(flb, output_fd, "match", "*", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(flb);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(flb);
        goto cleanup;
    }

    ret = wait_for_flag(&stale_device_observed, 5000);
    TEST_CHECK(ret == 0);

    ret = write_netdev_file(netdev_path, FLB_FALSE);
    TEST_CHECK(ret == 0);
    pthread_mutex_lock(&result_mutex);
    stale_device_removed = FLB_TRUE;
    pthread_mutex_unlock(&result_mutex);

    ret = wait_for_flag(&clean_snapshot_observed, 5000);
    TEST_CHECK(ret == 0);

    flb_stop(flb);
    flb_destroy(flb);

cleanup:
    unlink(netdev_path);
    rmdir(net_path);
    rmdir(procfs_path);
}

#endif

TEST_LIST = {
    {"diskstats", test_diskstats},
#ifdef FLB_SYSTEM_LINUX
    {"netdev_removes_stale_devices", test_netdev_removes_stale_devices},
#endif
    {NULL, NULL}
};
