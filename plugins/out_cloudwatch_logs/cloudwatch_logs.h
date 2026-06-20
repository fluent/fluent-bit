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

#ifndef FLB_OUT_CLOUDWATCH_LOGS_H
#define FLB_OUT_CLOUDWATCH_LOGS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_signv4.h>

#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

/*
 * Entity object used for associating the telemetry
 * in the PutLogEvent call
 */
typedef struct entity {
    struct entity_key_attributes *key_attributes;
    struct entity_attributes *attributes;
    int filter_count;
    int service_name_found;
    int environment_found;
    int name_source_found;
    int root_filter_count;
}entity;

/*
 * KeyAttributes used for CloudWatch Entity object
 * in the PutLogEvent call
 */
typedef struct entity_key_attributes {
    char *type;
    char *name;
    char *environment;
    char *account_id;
}entity_key_attributes;

/*
 * Attributes used for CloudWatch Entity object
 * in the PutLogEvent call
 */
typedef struct entity_attributes {
    char *platform_type;
    char *cluster_name;
    char *namespace;
    char *workload;
    char *node;
    char *instance_id;
    char *name_source;
}entity_attributes;

#define LOG_CLASS_STANDARD                  "STANDARD"
#define LOG_CLASS_STANDARD_LEN              8
#define LOG_CLASS_INFREQUENT_ACCESS         "INFREQUENT_ACCESS"
#define LOG_CLASS_INFREQUENT_ACCESS_LEN     17
/* log_group_class not configured; do not send the logGroupClass field in request */
#define LOG_CLASS_DEFAULT_TYPE              0
/* send configured & validated string in request */
#define LOG_CLASS_STANDARD_TYPE             1
#define LOG_CLASS_INFREQUENT_ACCESS_TYPE    2

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

    /* current log stream that we are sending records too */
    struct log_stream *current_stream;
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
    flb_sds_t group;

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

    /*
     * PutLogEvents entity object
     * variable that store service or infrastructure
     * information
     */
    struct entity *entity;

    struct mk_list _head;
};

struct flb_cloudwatch {
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
    const char *extra_user_agent;
    const char *external_id;
    const char *profile;
    const char *log_group_class;
    int log_group_class_type;
    int custom_endpoint;
    /* Should the plugin create the log group */
    int create_group;

    flb_sds_t group_name;
    flb_sds_t stream_name;

    /* Should requests to AWS services be retried */
    int retry_requests;

    /* If set to a number greater than zero, and newly create log group's retention policy is set to this many days. */
    int log_retention_days;

    /* must be freed on shutdown if custom_endpoint is not set */
    char *endpoint;

    /* templates */
    struct flb_record_accessor *ra_group;
    struct flb_record_accessor *ra_stream;

    /* stores log streams we're putting to */
    struct mk_list streams;

    /* The namespace to use for the metric */
    flb_sds_t metric_namespace;

    /* Metric dimensions is a list of lists. If you have only one list of
    dimensions, put the values as a comma seperated string. If you want to put
    list of lists, use the list as semicolon seperated strings. If your value
    is 'd1,d2;d3', we will consider it as [[d1, d2],[d3]]*/
    struct mk_list *metric_dimensions;

    /* Plugin output instance reference */
    struct flb_output_instance *ins;

    /*
     * Checks if kubernete filter is enabled
     * So the plugin knows when to scrape for Entity
     */

    int kubernete_metadata_enabled;

    int add_entity;
};

void flb_cloudwatch_ctx_destroy(struct flb_cloudwatch *ctx);

void log_stream_destroy(struct log_stream *stream);

#endif
