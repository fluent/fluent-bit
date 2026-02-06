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

/*
 * OpenTelemetry encoding benchmarks (OTLP logs, metrics, traces).
 * Usage: flb-bench-opentelemetry -m <mode> -f <input_file> [-i iterations]
 *
 * Modes:
 *   otlp-json-logs   OTLP-JSON logs -> Fluent Bit log events
 *                    (flb_opentelemetry_logs_json_to_msgpack)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_opentelemetry.h>

static long diff_ns(struct timespec *s, struct timespec *e)
{
    return (e->tv_sec - s->tv_sec) * 1000000000L + (e->tv_nsec - s->tv_nsec);
}

static int run_otlp_json_logs(char *json, size_t len, int iterations)
{
    int i;
    int ret;
    struct timespec ts, te;
    struct flb_log_event_encoder enc;
    int error_status;
    long d_ns;
    uint64_t total_bytes;
    double mibps;

    ret = flb_log_event_encoder_init(&enc, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        fprintf(stderr, "encoder init failed\n");
        return -1;
    }

    ret = flb_opentelemetry_logs_json_to_msgpack(&enc, json, len, NULL, &error_status);
    if (ret < 0) {
        fprintf(stderr, "OTLP encode failed (error_status=%d), file must be OTLP-JSON (resourceLogs...)\n", error_status);
        flb_log_event_encoder_destroy(&enc);
        return -1;
    }
    flb_log_event_encoder_reset(&enc);

    printf("Benchmarking OTLP-JSON logs encoding (flb_opentelemetry_logs_json_to_msgpack)\n");
    printf("------------------------------------------------------------------------\n\n");
    printf("Iterations   : %d\n", iterations);
    printf("JSON size    : %zu bytes\n", len);
    printf("------------------------------------------------------------------------\n\n");

    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (i = 0; i < iterations; i++) {
        flb_log_event_encoder_reset(&enc);
        ret = flb_opentelemetry_logs_json_to_msgpack(&enc, json, len, NULL, &error_status);
        if (ret < 0) {
            fprintf(stderr, "OTLP encode failed at iteration %d\n", i);
            flb_log_event_encoder_destroy(&enc);
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &te);
    flb_log_event_encoder_destroy(&enc);

    d_ns = diff_ns(&ts, &te);
    total_bytes = (uint64_t) len * (uint64_t) iterations;
    mibps = (double) total_bytes / d_ns * 1e9 / (1024.0 * 1024.0);

    printf("------------------------------------------------------------------------\n");
    printf("Total time   : %ld ns\n", d_ns);
    printf("Per call     : %ld ns\n", d_ns / (long) iterations);
    printf("Throughput   : %.2f MiB/s\n", mibps);
    printf("------------------------------------------------------------------------\n");
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -m <mode> -f <input_file> [-i iterations]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  otlp-json-logs   OTLP-JSON logs encoding\n");
    fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    int ret;
    int iterations = 100;
    char *input_file = NULL;
    char *mode = NULL;
    char *json;
    size_t len;
    int opt;

    while ((opt = getopt(argc, argv, "f:i:m:")) != -1) {
        switch (opt) {
        case 'f':
            input_file = optarg;
            break;
        case 'i':
            iterations = atoi(optarg);
            if (iterations <= 0) {
                fprintf(stderr, "Invalid -i (iterations): %s\n", optarg);
                return 1;
            }
            break;
        case 'm':
            mode = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (mode == NULL || input_file == NULL) {
        fprintf(stderr, "Error: -m and -f are required.\n\n");
        usage(argv[0]);
        return 1;
    }

    ret = flb_utils_read_file(input_file, &json, &len);
    if (ret != 0) {
        fprintf(stderr, "error reading %s\n", input_file);
        return 1;
    }

    if (strcmp(mode, "otlp-json-logs") == 0) {
        ret = run_otlp_json_logs(json, len, iterations);
    }
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        usage(argv[0]);
        free(json);
        return 1;
    }

    free(json);
    return ret != 0 ? 1 : 0;
}
