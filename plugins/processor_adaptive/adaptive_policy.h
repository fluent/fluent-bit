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

#ifndef FLB_PROCESSOR_ADAPTIVE_POLICY_H
#define FLB_PROCESSOR_ADAPTIVE_POLICY_H

#include <fluent-bit/flb_info.h>
#include <cfl/cfl.h>

#include <stdint.h>
#include <sys/types.h>

#include "adaptive_miner.h"

#define ADAPTIVE_KEEP               0
#define ADAPTIVE_DROP               1

/* Why a record was kept or dropped */
#define ADAPTIVE_REASON_PROTECTED   0   /* level or regex exemption          */
#define ADAPTIVE_REASON_POLICY      1   /* drop rate from the policy file    */
#define ADAPTIVE_REASON_ALLOWANCE   2   /* inside the per window allowance   */
#define ADAPTIVE_REASON_LOW_VOLUME  3   /* pattern too quiet to sample       */
#define ADAPTIVE_REASON_SAMPLED     4   /* automatic 1 in N sampling         */
#define ADAPTIVE_REASON_BUDGET      5   /* window byte budget exhausted      */
#define ADAPTIVE_REASON_EXEMPLAR    6   /* first of its pattern, over budget */
#define ADAPTIVE_REASON_UNMATCHED   7   /* no usable message key             */
#define ADAPTIVE_REASON_COUNT       8

#define ADAPTIVE_SAMPLE_OFF         0
#define ADAPTIVE_SAMPLE_LOG         1
#define ADAPTIVE_SAMPLE_SQRT        2
#define ADAPTIVE_SAMPLE_SUPPRESS    3

/* Result of loading a policy */
#define ADAPTIVE_POLICY_ERROR      -1
#define ADAPTIVE_POLICY_UNCHANGED   0
#define ADAPTIVE_POLICY_LOADED      1

struct adaptive_policy_entry {
    int by_id;
    uint64_t id;
    int token_count;
    int truncated;
    char **tokens;
    cfl_sds_t template_str;
    cfl_sds_t group;            /* NULL applies to every group */
    double drop_rate;
    struct cfl_list _head;
};

struct adaptive_policy {
    /* automatic behaviour */
    uint64_t window_ns;
    uint64_t allow;
    uint64_t min_events;
    int sample_mode;
    uint32_t max_rate;
    uint64_t budget_bytes;

    /* explicit per pattern rates, usually written by a controller */
    struct cfl_list entries;
    int entry_count;
    uint64_t generation;
    int file_loaded;
    time_t file_mtime;
    off_t file_size;

    /* budget window */
    uint64_t window_id;
    uint64_t win_kept_bytes;
};

struct adaptive_decision {
    int action;
    int reason;
    uint32_t sample_rate;       /* one kept record stands for this many */
    uint64_t suppressed;        /* drops folded into this kept record   */
};

struct adaptive_policy *adaptive_policy_create(int window_seconds, int allow,
                                               int min_events, int sample_mode,
                                               int max_rate, uint64_t budget_bytes);
void adaptive_policy_destroy(struct adaptive_policy *policy);

int adaptive_policy_sample_mode(const char *name);
const char *adaptive_policy_reason_name(int reason);

int adaptive_policy_load_buffer(struct adaptive_policy *policy,
                                const char *json, size_t len);
int adaptive_policy_load_file(struct adaptive_policy *policy, const char *path);

void adaptive_policy_decide(struct adaptive_policy *policy,
                            struct adaptive_pattern *pattern,
                            size_t bytes, uint64_t now, int is_protected,
                            struct adaptive_decision *decision);

#endif
