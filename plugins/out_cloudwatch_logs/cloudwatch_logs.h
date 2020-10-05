/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_OUT_CLOUDWATCH_LOGS_H
#define FLB_OUT_CLOUDWATCH_LOGS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>

/* buffers used for each flush */
struct cw_flush {
    /* temporary buffer for storing the serialized event messages */
    char *tmp_buf;
    size_t tmp_buf_size;
    /* current index of tmp_buf */
    size_t tmp_buf_offset;

    /* projected final size of the payload for this flush */
    size_t data_size;

    /* log events- each of these has a pointer to their message in tmp_buf */
    struct cw_event *events;
    int events_capacity;
    /* current event */
    int event_index;

    /* the payload of the API request */
    char *out_buf;
    size_t out_buf_size;

    /* buffer used to temporarily hold an event during processing */
    char *event_buf;
    size_t event_buf_size;

    /*
     * According to the docs:
     * PutLogEvents: 5 requests per second per log stream.
     * Additional requests are throttled. This quota can't be changed.
     * This plugin fast. A single flush might make more than 5 calls,
     * Then fail, then retry, then be too fast again, on and on.
     * I have seen this happen.
     * So we throttle ourselves if more than 5 calls are made per flush
     */
    int put_events_calls;
};

struct cw_event {
    char *json;
    size_t len;
    // TODO: re-usable in kinesis streams plugin if we make it timespec instead
    // uint64_t?
    unsigned long long timestamp;
};

struct log_stream {
    flb_sds_t name;
    flb_sds_t sequence_token;
    /*
     * log streams in CloudWatch do not expire; but our internal representations
     * of them are periodically cleaned up if they have been unused for too long
     */
    time_t expiration;

    /*
     * Used to track the "time span" of a single PutLogEvents payload
     * Which can not exceed 24 hours.
     */
    unsigned long long oldest_event;
    unsigned long long newest_event;

    struct mk_list _head;
};

void log_stream_destroy(struct log_stream *stream);

struct flb_cloudwatch {
    /*
     * TLS instances can not be re-used. So we have one for:
     * - Base cred provider (needed for EKS provider)
     * - STS Assume role provider
     * - The CloudWatch Logs client for this plugin
     */
    struct flb_tls cred_tls;
    struct flb_tls sts_tls;
    struct flb_tls client_tls;
    struct flb_aws_provider *aws_provider;
    struct flb_aws_provider *base_aws_provider;
    struct flb_aws_client *cw_client;

    /* configuration options */
    const char *log_stream_name;
    const char *log_stream_prefix;
    const char *log_group;
    const char *region;
    const char *sts_endpoint;
    const char *log_format;
    const char *role_arn;
    const char *log_key;
    int custom_endpoint;
    /* Should the plugin create the log group */
    int create_group;

    /* has the log group successfully been created */
    int group_created;

    /* must be freed on shutdown if custom_endpoint is not set */
    char *endpoint;

    /* if we're writing to a static log stream, we'll use this */
    struct log_stream stream;
    int stream_created;
    /* if the log stream is dynamic, we'll use this */
    struct mk_list streams;

    /* buffers for data processing and request payload */
    struct cw_flush *buf;
    /* The namespace to use for the metric */
    flb_sds_t metric_namespace;

    /* Metric dimensions is a list of lsits. If you have only one list of 
    dimensions, put the values as a comma seperated string. If you want to put
    list of lists, use the list as semicolon seperated strings. If your value
    is 'd1,d2;d3', we will consider it as [[d1, d2],[d3]]*/
    struct mk_list *metric_dimensions;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;
};

void flb_cloudwatch_ctx_destroy(struct flb_cloudwatch *ctx);

#endif
