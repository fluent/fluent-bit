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

#ifndef FLB_OUT_CLOUDWATCH_API
#define FLB_OUT_CLOUDWATCH_API

/*
 * The CloudWatch API documents that the maximum payload is 1,048,576 bytes.
 * This is the total size limit for the entire PutLogEvents request payload buffer.
 * Individual events are capped at MAX_EVENT_LEN (1,000,000 bytes) as a conservative
 * safety margin to account for JSON encoding overhead and per-event metadata.
 */
#define PUT_LOG_EVENTS_PAYLOAD_SIZE    1048576
#define MAX_EVENTS_PER_PUT             10000

/* number of characters needed to 'start' a PutLogEvents payload */
#define PUT_LOG_EVENTS_HEADER_LEN      72
/* number of characters needed per event in a PutLogEvents payload */
#define PUT_LOG_EVENTS_PER_EVENT_LEN   42
/* number of characters needed to 'end' a PutLogEvents payload */
#define PUT_LOG_EVENTS_FOOTER_LEN      4

/*
 * https://docs.aws.amazon.com/applicationsignals/latest/APIReference/API_Service.html
 * Maximum number of character limits including both the KeyAttributes key and its value
 */
#define KEY_ATTRIBUTES_MAX_LEN 1100
/* Maximum number of character limits including both the Attributes key and its value */
#define ATTRIBUTES_MAX_LEN 300

/*
 * https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
 * AWS CloudWatch's documented maximum event size is 1,048,576 bytes (1 MiB),
 * including JSON encoding overhead (structure, escaping, etc.).
 * 
 * Setting MAX_EVENT_LEN to 1,000,000 bytes (1 MB) provides a ~4.6% safety margin
 * to account for JSON encoding overhead and ensure reliable operation.
 * Testing confirmed messages up to 1,048,546 bytes (encoding to 1,048,586 bytes)
 * succeed, though we use a conservative limit for production safety.
 */
#define MAX_EVENT_LEN      1000000

/* Prefix used for entity fields only */
#define AWS_ENTITY_PREFIX "aws_entity"
#define AWS_ENTITY_PREFIX_LEN 10

#include "cloudwatch_logs.h"

void cw_flush_destroy(struct cw_flush *buf);

int process_and_send(struct flb_cloudwatch *ctx, const char *input_plugin,
                     struct cw_flush *buf, flb_sds_t tag,
                     const char *data, size_t bytes, int event_type,
                     struct flb_config *config);
int create_log_stream(struct flb_cloudwatch *ctx, struct log_stream *stream, int can_retry);
struct log_stream *get_log_stream(struct flb_cloudwatch *ctx, flb_sds_t tag,
                                  const msgpack_object map);
int put_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                   struct log_stream *stream,
                   size_t payload_size);
int create_log_group(struct flb_cloudwatch *ctx, struct log_stream *stream);
int compare_events(const void *a_arg, const void *b_arg);

#endif
