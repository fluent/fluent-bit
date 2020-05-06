/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
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

#ifndef FLB_LIB_H
#define FLB_LIB_H

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>

/* Lib engine status */
#define FLB_LIB_ERROR     -1
#define FLB_LIB_NONE       0
#define FLB_LIB_OK         1

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

FLB_EXPORT void flb_init_env();
FLB_EXPORT flb_ctx_t *flb_create();
FLB_EXPORT void flb_destroy(flb_ctx_t *ctx);
FLB_EXPORT int flb_input(flb_ctx_t *ctx, const char *input, void *data);
FLB_EXPORT int flb_output(flb_ctx_t *ctx, const char *output, void *data);
FLB_EXPORT int flb_filter(flb_ctx_t *ctx, const char *filter, void *data);
FLB_EXPORT int flb_input_set(flb_ctx_t *ctx, int ffd, ...);
FLB_EXPORT int flb_output_set(flb_ctx_t *ctx, int ffd, ...);
FLB_EXPORT int flb_output_set_callback(flb_ctx_t *ctx, int ffd, char *name,
                                       void (*cb)(char *, void *, void *));

FLB_EXPORT int flb_filter_set(flb_ctx_t *ctx, int ffd, ...);
FLB_EXPORT int flb_service_set(flb_ctx_t *ctx, ...);
FLB_EXPORT int  flb_lib_free(void *data);
FLB_EXPORT double flb_time_now();

/* start stop the engine */
FLB_EXPORT int flb_start(flb_ctx_t *ctx);
FLB_EXPORT int flb_stop(flb_ctx_t *ctx);

/* data ingestion for "lib" input instance */
FLB_EXPORT int flb_lib_push(flb_ctx_t *ctx, int ffd, const void *data, size_t len);
FLB_EXPORT int flb_lib_config_file(flb_ctx_t *ctx, const char *path);

#endif
