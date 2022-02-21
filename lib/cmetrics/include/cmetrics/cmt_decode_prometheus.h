/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#ifndef CMT_DECODE_PROMETHEUS_H
#define CMT_DECODE_PROMETHEUS_H

#include <stdbool.h>

#include "monkey/mk_core/mk_list.h"
#include <cmetrics/cmetrics.h>

#define CMT_DECODE_PROMETHEUS_SUCCESS                     0
#define CMT_DECODE_PROMETHEUS_SYNTAX_ERROR                1
#define CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR           10
#define CMT_DECODE_PROMETHEUS_PARSE_UNSUPPORTED_TYPE     20
#define CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT_EXCEEDED   30
#define CMT_DECODE_PROMETHEUS_CMT_SET_ERROR              40
#define CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR           50
#define CMT_DECODE_PROMETHEUS_PARSE_VALUE_FAILED         60
#define CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED     70

#define CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT 128

struct cmt_decode_prometheus_context_sample {
    double value;
    uint64_t timestamp;
    size_t label_count;
    cmt_sds_t label_values[CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT];

    struct mk_list _head;
};

struct cmt_decode_prometheus_context_metric {
    cmt_sds_t name_orig;
    char *ns;
    char *subsystem;
    char *name;
    int type;
    cmt_sds_t docstring;
    size_t label_count;
    cmt_sds_t labels[CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT];
    struct mk_list samples;
};

struct cmt_decode_prometheus_parse_opts {
    int start_token;
    uint64_t default_timestamp;
    char *errbuf;
    size_t errbuf_size;
    bool skip_unsupported_type;
};

struct cmt_decode_prometheus_context {
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    int errcode;
    cmt_sds_t strbuf;
    struct cmt_decode_prometheus_context_metric metric;
};

#define YY_DECL int cmt_decode_prometheus_lex \
               (YYSTYPE * yylval_param, \
               void* yyscanner, \
               struct cmt_decode_prometheus_context *context)

#include "cmt_decode_prometheus_parser.h"

#ifndef FLEX_SCANNER
// lexer header should not be included in the generated lexer c file,
// which defines FLEX_SCANNER
#include "cmt_decode_prometheus_lexer.h"
#endif

int cmt_decode_prometheus_create(
        struct cmt **out_cmt,
        const char *in_buf,
        size_t in_size,
        struct cmt_decode_prometheus_parse_opts *opts);
void cmt_decode_prometheus_destroy(struct cmt *cmt);

#endif
