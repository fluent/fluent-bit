/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_ML_H
#define FLB_ML_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>

/* Types available */
#define FLB_ML_COUNT     0    /* concatenate N consecutive records  */
#define FLB_ML_REGEX     1    /* pattern is a regular expression    */
#define FLB_ML_ENDSWITH  2    /* record key/content ends with 'abc' */
#define FLB_ML_EQ        3    /* record key/content equaks 'abc'    */

/* Rule types */
#define FLB_ML_RULE_STATE_START 0
#define FLB_ML_RULE_STATE_PART  1
#define FLB_ML_RULE_STATE_END   2

/* Payload types */
#define FLB_ML_TYPE_TEXT        0   /* raw text */
#define FLB_ML_TYPE_RECORD      1   /* Fluent Bit msgpack record */
#define FLB_ML_TYPE_MAP         2   /* msgpack object/map (k/v pairs) */

/* Default multiline buffer size: 4Kb */
#define FLB_ML_BUF_SIZE         1024*4

/* Maximum number of groups per stream */
#define FLB_ML_MAX_GROUPS       6

struct flb_ml;
struct flb_ml_stream;

struct flb_ml_rule {
    /* If the rule contains a 'start_state' this flag is turned on */
    int start_state;

    /* Name of the rule (state name) */
    struct mk_list from_states;

    /*
     * Defined 'to_state' in the rule. Note that this work only at definition
     * since we do a mapping to multiple possible rules having the same
     * name.
     */
    flb_sds_t to_state;

    struct mk_list to_state_map;

    /* regex content pattern */
    struct flb_regex *regex;

    /* regex end pattern */
    struct flb_regex *regex_end;

    struct mk_list _head;
};

struct flb_ml_stream_group {
    flb_sds_t name;           /* group name, unique identifier */

    uint64_t last_flush;      /* last flush/check time */

    int counter_lines;        /* counter for the number of lines */

    /* Multiline content buffer */
    flb_sds_t buf;

    /* internal state */
    int first_line;           /* first line of multiline message ? */

    struct flb_ml_rule *rule_to_state;

    /* packaging buffers */
    msgpack_sbuffer mp_sbuf;  /* temporary msgpack buffer              */
    msgpack_packer mp_pck;    /* temporary msgpack packer              */
    struct flb_time mp_time;  /* multiline time parsed from first line */

    struct mk_list _head;
};

struct flb_ml_stream {
    flb_sds_t name;           /* Name of the stream, mostly for debugging purposes */
    struct mk_list groups;    /* Groups inside a stream */

    /* Flush callback and opaque data type */
    int (*cb_flush) (struct flb_ml *,
                     struct flb_ml_stream *,
                     void *cb_data,
                     void *buf_data,
                     size_t buf_size);
    void *cb_data;

    struct mk_list _head;
};

struct flb_ml {
    int type;                 /* type: COUNT, REGEX, ENDSWITH or EQ */
    int negate;               /* negate start pattern ? */

    flb_sds_t name;

    /*
     * If 'multiline type' is ENDSWITH or EQ, a 'match_str' string is passed
     * so we can compare against it. We don't use a regex pattern for efficiency.
     */
    flb_sds_t match_str;

    /*
     * The 'key' name that contains the multiline message. For REGEX, ENDSWITH and
     * EQ types, the conditions are applied to 'key_content' unless 'key_pattern'
     * is set, on that case 'key_content' is used as a raw buffer and appended
     * as part of the multiline message.
     */
    flb_sds_t key_content;

    /*
     * Optional: define a 'key' name that matches the pattern to decide if the
     * line is complete or a continuation.
     *
     * This is not mandatory, most of the rules works directly on 'key_content'
     * but other use-cases like 'CRI' uses a different 'key' to define if the
     * line is complete or not.
     */
    flb_sds_t key_pattern;


    /*
     * Optional: define a 'key' name that specify a specific group of logs.
     * As an example, consider containerized logs coming from Docker or CRI
     * where the logs must be group by stream 'stdout' and 'stderr'. On that
     * case key_group = 'stream'.
     *
     * If the origin stream will not have groups, this can be null and the
     * multiline context creator will only use a default group for everything
     * under the same stream.
     */
    flb_sds_t key_group;

    /* Flush interval */
    int flush_ms;

    /* flush callback */
    int (*cb_flush)(struct flb_ml *,           /* multiline context */
                    struct flb_ml_stream *,    /* stream context */
                    void *,                    /* opaque data */
                    char *,                    /* text buffer */
                    size_t);                   /* buffer length */

    void *cb_data;                             /* opaque data */

    /* internal */
    struct flb_parser *parser;                 /* parser context */
    flb_sds_t parser_name;                     /* parser name for delayed init */

    /*
     * Every multiline context has N streams, a stream represent a source
     * of data. To avoid having 'multiple' context of 'multiline' we use
     * streams.
     */
    struct mk_list streams;

    /*
     * If multiline type is REGEX, it needs a set of pre-defined rules to deal
     * with messages.
     */
    struct mk_list regex_rules;

    /* Fluent Bit parent context */
    struct flb_config *config;

    /* Link node: every multiline context is linked on config->ml list */
    struct mk_list _head;
};

struct flb_ml *flb_ml_create(struct flb_config *ctx,
                             char *name,
                             int type, char *match_str, int negate,
                             int flush_ms,
                             char *key_content,
                             char *key_group,
                             char *key_pattern,
                             struct flb_parser *parser_ctx,
                             char *parser_name);

int flb_ml_destroy(struct flb_ml *ml);

int flb_ml_register_context(struct flb_ml *ml, struct flb_ml_stream *mst,
                            struct flb_ml_stream_group *group,
                            struct flb_time *tm, msgpack_object *map);

int flb_ml_append(struct flb_ml *ml, struct flb_ml_stream *mst,
                  int type,
                  struct flb_time *tm, void *buf, size_t size);
int flb_ml_append_object(struct flb_ml *ml,
                         struct flb_ml_stream *mst,
                         struct flb_time *tm, msgpack_object *obj);

int flb_ml_parsers_init(struct flb_config *ctx);
int flb_ml_auto_flush_start(struct flb_ml *ml);

int flb_ml_flush_stream_group(struct flb_ml *ml, struct flb_ml_stream *mst,
                              struct flb_ml_stream_group *group);

/* Multiline streams */
struct flb_ml_stream *flb_ml_stream_create(struct flb_ml *ml,
                                           char *name,
                                           int (*cb_flush) (struct flb_ml *,
                                                            struct flb_ml_stream *,
                                                            void *cb_data,
                                                            void *buf_data,
                                                            size_t buf_size),
                                           void *cb_data);

int flb_ml_stream_destroy(struct flb_ml_stream *mst);

struct flb_ml_stream_group *flb_ml_stream_group_get(struct flb_ml *ml,
                                                    struct flb_ml_stream *mst,
                                                    msgpack_object *full_map);

/* Regex Rules */
int flb_ml_rule_create(struct flb_ml *ml,
                       flb_sds_t from_states,
                       char *regex_pattern,
                       flb_sds_t to_state,
                       char *end_pattern);
void flb_ml_rule_destroy(struct flb_ml_rule *rule);
void flb_ml_rule_destroy_all(struct flb_ml *ml);

int flb_ml_init(struct flb_ml *ml);

int flb_ml_type_lookup(char *str);

#include "flb_ml_mode.h"

#endif
