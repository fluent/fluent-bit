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

#ifndef FLB_OUT_FIREHOSE_H
#define FLB_OUT_FIREHOSE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/aws/flb_aws_aggregation.h>

#define DEFAULT_TIME_KEY_FORMAT "%Y-%m-%dT%H:%M:%S"

#define FLB_KINESIS_DEFAULT_HTTPS_PORT    443

/* buffers used for each flush */
struct flush {
    /* temporary buffer for storing the serialized event messages */
    char *tmp_buf;
    size_t tmp_buf_size;
    /* current index of tmp_buf */
    size_t tmp_buf_offset;

    /* projected final size of the payload for this flush */
    size_t data_size;

    /* log records- each of these has a pointer to their message in tmp_buf */
    struct firehose_event *events;
    int events_capacity;
    /* current event */
    int event_index;

    /* the payload of the API request */
    char *out_buf;
    size_t out_buf_size;

    /* buffer used to temporarily hold an event during processing */
    char *event_buf;
    size_t event_buf_size;

    /* aggregation buffer for simple_aggregation mode */
    struct flb_aws_agg_buffer agg_buf;
    int agg_buf_initialized;

    int records_sent;
    int records_processed;
};

struct firehose_event {
    char *json;
    size_t len;
    struct timespec timestamp;
};

struct flb_firehose {
    /*
     * TLS instances can not be re-used. So we have one for:
     * - Base cred provider (needed for EKS provider)
     * - STS Assume role provider
     * - The CloudWatch Logs client for this plugin
     */
    struct flb_tls *cred_tls;
    struct flb_tls *sts_tls;
    struct flb_tls *client_tls;
    struct flb_aws_provider *aws_provider;
    struct flb_aws_provider *base_aws_provider;
    struct flb_aws_client *firehose_client;

    /* configuration options */
    const char *delivery_stream;
    const char *time_key;
    const char *time_key_format;
    const char *region;
    const char *role_arn;
    const char *log_key;
    const char *external_id;
    char *sts_endpoint;
    uint16_t port;
    char *profile;
    int custom_endpoint;
    int retry_requests;
    int compression;
    int simple_aggregation;

    /* must be freed on shutdown if custom_endpoint is not set */
    char *endpoint;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

void flb_firehose_ctx_destroy(struct flb_firehose *ctx);

#endif
