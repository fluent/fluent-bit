/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#ifndef CTR_H
#define CTR_H

#define CTR_FALSE   0
#define CTR_TRUE    !CTR_FALSE

#include <ctraces/ctr_info.h>
#include <ctraces/ctr_compat.h>

/* local libs */
#include <cfl/cfl.h>
#include <mpack/mpack.h>

#include <stdio.h>
#include <stdlib.h>

/* ctrace options creation keys */
#define CTR_OPTS_TRACE_ID   0

/* options is unused for now */
struct ctrace_opts {
    /* windows compiler: error C2016: C requires that a struct or union have at least one member */
    int _make_windows_happy;
};

struct ctrace {
    /*
     * last_span_id represents the higher span id number assigned, every time
     * a new span is created this value gets incremented.
     */
    uint64_t last_span_id;

    /*
     * When the user creates a new resource, we add it to a linked list so on
     * every span we just keep a reference.
     */
    struct cfl_list resource_spans;

    /*
     * This 'span_list' is used for internal purposes only when a caller needs to
     * iterate all spans linearly without getting inside a loop with resource_span, scope_spans, etc.
     *
     * note: every 'span' is linked to a 'scope_span' and to 'span_list' (this structure)
     */
    struct cfl_list span_list;

    /* logging */
    int log_level;
    void (*log_cb)(void *, int, const char *, int, const char *);
};

struct ctrace *ctr_create(struct ctrace_opts *opts);
void ctr_destroy(struct ctrace *ctx);

/* options */
void ctr_opts_init(struct ctrace_opts *opts);
void ctr_opts_set(struct ctrace_opts *opts, int value, char *val);
void ctr_opts_exit(struct ctrace_opts *opts);

/* headers that are needed in general */
#include <ctraces/ctr_info.h>
#include <ctraces/ctr_id.h>
#include <ctraces/ctr_random.h>
#include <ctraces/ctr_version.h>
#include <ctraces/ctr_span.h>
#include <ctraces/ctr_scope.h>
#include <ctraces/ctr_link.h>
#include <ctraces/ctr_attributes.h>
#include <ctraces/ctr_log.h>
#include <ctraces/ctr_resource.h>

/* encoders */
#include <ctraces/ctr_encode_text.h>
#include <ctraces/ctr_encode_msgpack.h>
#include <ctraces/ctr_encode_opentelemetry.h>

/* decoders */
#include <ctraces/ctr_decode_opentelemetry.h>



#endif
