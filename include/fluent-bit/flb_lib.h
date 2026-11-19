/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
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

#ifndef FLB_LIB_H
#define FLB_LIB_H

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>

struct flb_input_instance;

/* Lib engine status */
#define FLB_LIB_ERROR     -1
#define FLB_LIB_NONE       0
#define FLB_LIB_OK         1
#define FLB_LIB_NO_CONFIG_MAP 2

/* Library mode context data */
struct flb_lib_ctx {
    int status;
    struct mk_event_loop *event_loop;
    struct mk_event *event_channel;
    struct flb_config *config;
};

/* Used on out_lib to define a callback and further opaque data */
struct flb_lib_out_cb {
    int (*cb) (void *record, size_t size, void *data);
    void *data;
};

/* For Fluent Bit library callers, we only export the following symbols */
typedef struct flb_lib_ctx         flb_ctx_t;

struct flb_processor;

FLB_EXPORT void flb_init_env();
FLB_EXPORT flb_ctx_t *flb_create();
FLB_EXPORT void flb_destroy(flb_ctx_t *ctx);
FLB_EXPORT int flb_input(flb_ctx_t *ctx, const char *input, void *data);
FLB_EXPORT int flb_input_set_processor(flb_ctx_t *ctx, int ffd, struct flb_processor *proc);
FLB_EXPORT int flb_output(flb_ctx_t *ctx, const char *output, struct flb_lib_out_cb *cb);
FLB_EXPORT int flb_output_set_processor(flb_ctx_t *ctx, int ffd, struct flb_processor *proc);
FLB_EXPORT int flb_filter(flb_ctx_t *ctx, const char *filter, void *data);
FLB_EXPORT int flb_input_set(flb_ctx_t *ctx, int ffd, ...);
FLB_EXPORT int flb_input_set_test(flb_ctx_t *ctx, int ffd, char *test_name,
                                  void (*in_callback) (void *, int, int,
                                                       void *, size_t, void *),
                                  void *in_callback_data);
FLB_EXPORT int flb_input_property_check(flb_ctx_t *ctx, int ffd, char *key, char *val);
FLB_EXPORT int flb_output_property_check(flb_ctx_t *ctx, int ffd, char *key, char *val);
FLB_EXPORT int flb_filter_property_check(flb_ctx_t *ctx, int ffd, char *key, char *val);
FLB_EXPORT int flb_output_set(flb_ctx_t *ctx, int ffd, ...);
FLB_EXPORT int flb_output_set_test(flb_ctx_t *ctx, int ffd, char *test_name,
                                   void (*out_callback) (void *, int, int,
                                                         void *, size_t, void *),
                                   void *out_callback_data,
                                   void *test_ctx);
FLB_EXPORT int flb_output_set_test_with_ctx_callback(
                                   flb_ctx_t *ctx, int ffd, char *test_name,
                                   void (*out_callback) (void *, int, int,
                                                         void *, size_t, void *),
                                   void *out_callback_data,
                                   void *test_ctx,
                                   void *(*test_ctx_callback) (
                                           struct flb_config *,
                                           struct flb_input_instance *,
                                           void *, void *));
FLB_EXPORT int flb_output_set_callback(flb_ctx_t *ctx, int ffd, char *name,
                                       void (*cb)(char *, void *, void *));
FLB_EXPORT int flb_output_set_http_test(flb_ctx_t *ctx, int ffd, char *test_name,
                                        void (*out_response) (void *, int, int, void *, size_t, void *),
                                        void *out_callback_data);

FLB_EXPORT int flb_filter_set(flb_ctx_t *ctx, int ffd, ...);
FLB_EXPORT int flb_service_set(flb_ctx_t *ctx, ...);
FLB_EXPORT int  flb_lib_free(void *data);
FLB_EXPORT double flb_time_now();

/* start stop the engine */
FLB_EXPORT int flb_start(flb_ctx_t *ctx);
FLB_EXPORT int flb_start_trace(flb_ctx_t *ctx);
FLB_EXPORT int flb_stop(flb_ctx_t *ctx);
FLB_EXPORT int flb_loop(flb_ctx_t *ctx);

/* data ingestion for "lib" input instance */
FLB_EXPORT int flb_lib_push(flb_ctx_t *ctx, int ffd, const void *data, size_t len);
FLB_EXPORT int flb_lib_config_file(flb_ctx_t *ctx, const char *path);

/* Emulate ingestions of HTTP responses for output plugins */
FLB_EXPORT int flb_lib_response(flb_ctx_t *ctx, int ffd, int status, const void *data, size_t len);

/* library context handling */
FLB_EXPORT void flb_context_set(flb_ctx_t *ctx);
FLB_EXPORT flb_ctx_t *flb_context_get();

FLB_EXPORT void flb_cf_context_set(struct flb_cf *cf);
FLB_EXPORT struct flb_cf *flb_cf_context_get();

#endif
