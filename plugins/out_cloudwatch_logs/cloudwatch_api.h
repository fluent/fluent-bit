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

#ifndef FLB_OUT_CLOUDWATCH_API
#define FLB_OUT_CLOUDWATCH_API

/*
 * The CloudWatch API documents that the maximum payload is 1,048,576 bytes
 * For reasons that are under investigation, using that number in this plugin
 * leads to API errors. No issues have been seen setting it to 1,000,000 bytes.
 */
#define PUT_LOG_EVENTS_PAYLOAD_SIZE    1048576
#define MAX_EVENTS_PER_PUT             10000

/* number of characters needed to 'start' a PutLogEvents payload */
#define PUT_LOG_EVENTS_HEADER_LEN      72
/* number of characters needed per event in a PutLogEvents payload */
#define PUT_LOG_EVENTS_PER_EVENT_LEN   42
/* number of characters needed to 'end' a PutLogEvents payload */
#define PUT_LOG_EVENTS_FOOTER_LEN      4

/* 256KiB minus 26 bytes for the event */
#define MAX_EVENT_LEN      262118

#include "cloudwatch_logs.h"

void cw_flush_destroy(struct cw_flush *buf);

int process_and_send(struct flb_cloudwatch *ctx, const char *input_plugin, struct cw_flush *buf,
                     struct log_stream *stream,
                     const char *data, size_t bytes);
int create_log_stream(struct flb_cloudwatch *ctx, struct log_stream *stream);
struct log_stream *get_log_stream(struct flb_cloudwatch *ctx,
                                  const char *tag, int tag_len);
int put_log_events(struct flb_cloudwatch *ctx, struct cw_flush *buf,
                   struct log_stream *stream,
                   size_t payload_size);
int create_log_group(struct flb_cloudwatch *ctx);
int compare_events(const void *a_arg, const void *b_arg);

#endif
