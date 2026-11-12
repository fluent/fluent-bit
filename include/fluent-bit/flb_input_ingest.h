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

#ifndef FLB_INPUT_INGEST_H
#define FLB_INPUT_INGEST_H

#include <stddef.h>

/*
 * Host-driven ingestion
 * =====================
 * An input instance configured with 'source.mode external' does not start its
 * native collection (listener, timer, file). A host, such as an embedding
 * program, a test or the browser SDK, submits payloads with
 * flb_input_ingest_submit(). The payload is copied, queued in the input
 * ingress queue and later handed to the plugin 'cb_ingest' callback on the
 * event loop that owns the input, where the plugin runs its regular
 * processing.
 */

/* Collection modes (input property 'source.mode') */
#define FLB_INPUT_SOURCE_NATIVE    0
#define FLB_INPUT_SOURCE_EXTERNAL  1

/* Payload kinds: bit values, a plugin advertises them in 'ingest_kinds' */
#define FLB_INPUT_INGEST_STREAM_BYTES  1   /* chunk of a byte stream      */
#define FLB_INPUT_INGEST_HTTP_REQUEST  2   /* one assembled HTTP request  */

/* Admission results */
#define FLB_INPUT_INGEST_OK              0  /* payload queued                  */
#define FLB_INPUT_INGEST_ERROR          -1  /* invalid arguments or no memory  */
#define FLB_INPUT_INGEST_BUSY           -2  /* no capacity: nothing consumed   */
#define FLB_INPUT_INGEST_TOO_LARGE      -3  /* can never fit: permanent        */
#define FLB_INPUT_INGEST_NOT_SUPPORTED  -4  /* no external mode or no adapter  */
#define FLB_INPUT_INGEST_NOT_RUNNING    -5  /* admission is closed             */
#define FLB_INPUT_INGEST_FAILED         -6  /* stream is in a failed state     */

/* Reply outcomes: every admitted request gets exactly one */
#define FLB_INPUT_INGEST_REPLIED          0  /* the plugin produced a reply     */
#define FLB_INPUT_INGEST_REPLY_FAILED     1  /* dispatched, no reply available  */
#define FLB_INPUT_INGEST_REPLY_CANCELLED  2  /* never dispatched                */

/* Limits */
#define FLB_INPUT_INGEST_EVENT_MAX         (1024 * 1024)       /* per payload  */
#define FLB_INPUT_INGEST_QUEUE_BYTE_LIMIT  (16 * 1024 * 1024)  /* per input    */
#define FLB_INPUT_INGEST_PASS_EVENTS       32                  /* per dispatch */
#define FLB_INPUT_INGEST_PASS_BYTES        (1024 * 1024)       /* per dispatch */
#define FLB_INPUT_INGEST_HEADER_MAX        64                  /* per request  */

struct flb_input_instance;

struct flb_input_ingest_header {
    const char *name;
    size_t      name_len;
    const char *value;
    size_t      value_len;
};

/* Context for FLB_INPUT_INGEST_HTTP_REQUEST */
struct flb_input_ingest_request {
    const char *method;
    size_t      method_len;
    const char *path;                  /* path including the query string */
    size_t      path_len;
    const struct flb_input_ingest_header *headers;
    size_t      header_count;
};

/*
 * Event received by 'cb_ingest'. Everything is borrowed for the duration of
 * the callback: copy whatever must be retained.
 */
struct flb_input_ingest_event {
    int         kind;
    const char *data;                  /* stream bytes or request body */
    size_t      size;

    /* FLB_INPUT_INGEST_HTTP_REQUEST only; strings are NUL terminated */
    const char *method;
    size_t      method_len;
    const char *path;
    size_t      path_len;
    const struct flb_input_ingest_header *headers;
    size_t      header_count;

    void       *priv;                  /* core use */
};

struct flb_input_ingest_reply {
    int         status;
    const struct flb_input_ingest_header *headers;
    size_t      header_count;
    const char *body;
    size_t      body_size;
};

/*
 * Reply callback. It runs once per admitted request on the event loop that
 * owns the input. 'reply' is only set for FLB_INPUT_INGEST_REPLIED and it is
 * borrowed for the duration of the call.
 */
typedef void (*flb_input_ingest_reply_cb)(int outcome,
                                          const struct flb_input_ingest_reply *reply,
                                          void *data);

/*
 * Submit a payload to an input instance in external mode. It can be called
 * from any thread while the instance is alive. The payload and its context
 * are copied, so the caller memory can be released when the call returns. It
 * never waits for queue capacity or for processing: FLB_INPUT_INGEST_OK only
 * means the payload was queued.
 */
int flb_input_ingest_submit(struct flb_input_instance *ins,
                            int kind,
                            const void *data, size_t size,
                            const struct flb_input_ingest_request *request,
                            flb_input_ingest_reply_cb reply_cb,
                            void *reply_data);

/* Adapter side: deliver the reply of the request being dispatched */
int flb_input_ingest_event_reply(const struct flb_input_ingest_event *event,
                                 const struct flb_input_ingest_reply *reply);

/*
 * Adapter side: the stream cannot continue. Queued payloads are discarded and
 * later submissions return FLB_INPUT_INGEST_FAILED.
 */
void flb_input_ingest_fail(struct flb_input_instance *ins);

/* Core: close admission and cancel what is still queued */
void flb_input_ingest_close(struct flb_input_instance *ins);

/* Core: enable the ingress queue of an instance in external mode */
int flb_input_ingest_enable(struct flb_input_instance *ins);

#endif
