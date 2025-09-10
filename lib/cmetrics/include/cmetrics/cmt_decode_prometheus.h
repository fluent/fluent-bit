/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <cmetrics/cmt_info.h>

#ifdef CMT_HAVE_PROMETHEUS_TEXT_DECODER

#include <stdbool.h>

#include <cmetrics/cmetrics.h>
#include <stdint.h>

#define CMT_DECODE_PROMETHEUS_SUCCESS                     0
#define CMT_DECODE_PROMETHEUS_SYNTAX_ERROR                1
#define CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR           10
#define CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT_EXCEEDED   30
#define CMT_DECODE_PROMETHEUS_CMT_SET_ERROR              40
#define CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR           50
#define CMT_DECODE_PROMETHEUS_PARSE_VALUE_FAILED         60
#define CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED     70
#define CMT_DECODE_PROMETHEUS_SAMPLE_VALUE_TOO_LONG      80

#define CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT 128

enum cmt_decode_prometheus_context_sample_type {
    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_NORMAL = 0,
    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_BUCKET = 1,
    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM = 2,
    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT = 3
};

struct cmt_decode_prometheus_context_sample {
    char value1[64];
    char value2[64];
    int type;
    cfl_sds_t label_values[CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT];

    struct cfl_list _head;
};

struct cmt_decode_prometheus_context_metric {
    cfl_sds_t name_orig;
    char *ns;
    char *subsystem;
    char *name;
    int type;
    int current_sample_type;
    cfl_sds_t docstring;
    size_t label_count;
    cfl_sds_t labels[CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT];
    struct cfl_list samples;
};

struct cmt_decode_prometheus_parse_opts {
    int start_token;
    uint64_t default_timestamp;
    uint64_t override_timestamp;
    char *errbuf;
    size_t errbuf_size;
};

struct cmt_decode_prometheus_context {
    union {
        struct cmt_summary *summary;
        struct cmt_histogram *histogram;
    } current;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    int errcode;
    cfl_sds_t strbuf;
    struct cmt_decode_prometheus_context_metric metric;
};

#define LEX_DECL int cmt_decode_prometheus_lex \
               (YYSTYPE * yylval_param, \
               void* yyscanner, \
               struct cmt_decode_prometheus_context *context)

#define YY_DECL LEX_DECL

#include "cmt_decode_prometheus_parser.h"

#ifndef FLEX_SCANNER
// lexer header should not be included in the generated lexer c file,
// which defines FLEX_SCANNER
#include "cmt_decode_prometheus_lexer.h"
#endif

LEX_DECL; /* Declear as an entity of yylex function declaration. */

int cmt_decode_prometheus_create(
        struct cmt **out_cmt,
        const char *in_buf,
        size_t in_size,
        struct cmt_decode_prometheus_parse_opts *opts);
void cmt_decode_prometheus_destroy(struct cmt *cmt);

#endif /* CMT_HAVE_PROMETHEUS_TEXT_DECODER */

#endif
