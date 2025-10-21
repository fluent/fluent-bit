/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

/* Types available */
#define FLB_ML_REGEX     1    /* pattern is a regular expression    */
#define FLB_ML_ENDSWITH  2    /* record key/content ends with 'abc' */
#define FLB_ML_EQ        3    /* record key/content equaks 'abc'    */

/* Rule types */
#define FLB_ML_RULE_STATE_START 0
#define FLB_ML_RULE_STATE_PART  1
#define FLB_ML_RULE_STATE_END   2

/* Payload types */
#define FLB_ML_TYPE_TEXT        0    /* raw text */
#define FLB_ML_TYPE_RECORD      1    /* Fluent Bit msgpack record */
#define FLB_ML_TYPE_MAP         2    /* msgpack object/map (k/v pairs) */
#define FLB_ML_TYPE_EVENT       3    /* Fluent Bit decoded event */

#define FLB_ML_FLUSH_TIMEOUT    4000 /* Flush timeout default (milliseconds) */

/* Default multiline buffer size: 4Kb */
#define FLB_ML_BUF_SIZE         1024*4

/* Default limit for concatenated multiline messages: 2MB */
#define FLB_ML_BUFFER_LIMIT_DEFAULT_STR "2MB"
#define FLB_ML_BUFFER_LIMIT_DEFAULT     (1024 * 1024 * 2)

/* Return codes */
#define FLB_MULTILINE_OK         0
#define FLB_MULTILINE_PROCESSED  1 /* Reserved */
#define FLB_MULTILINE_TRUNCATED  2

/* Maximum number of groups per stream */
#define FLB_ML_MAX_GROUPS       6

struct flb_ml;
struct flb_ml_parser;
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
    msgpack_sbuffer mp_md_sbuf; /* temporary msgpack buffer              */
    msgpack_packer mp_md_pck;   /* temporary msgpack packer              */

    msgpack_sbuffer mp_sbuf;    /* temporary msgpack buffer              */
    msgpack_packer mp_pck;      /* temporary msgpack packer              */
    struct flb_time mp_time;    /* multiline time parsed from first line */
    int truncated;              /* was the buffer truncated?         */

    /* parent stream reference */
    struct flb_ml_stream *stream;

    struct mk_list _head;
};

struct flb_ml_stream {
    uint64_t id;
    flb_sds_t name;           /* name of the stream, mostly for debugging purposes */
    struct mk_list groups;    /* groups inside a stream */

    /* Flush callback and opaque data type */
    int (*cb_flush) (struct flb_ml_parser *,
                     struct flb_ml_stream *,
                     void *cb_data,
                     char *buf_data,
                     size_t buf_size);
    void *cb_data;

    struct flb_ml_stream_group *last_stream_group;

    /* runtime flags */
    int forced_flush;

    /* parent context */
    struct flb_ml *ml;

    /* reference to parent instance */
    struct flb_ml_parser_ins *parser;

    struct mk_list _head;
};

/* Multiline Parser definition (no running state, just definition) */
struct flb_ml_parser {
    int type;                 /* type: REGEX, ENDSWITH or EQ */
    int negate;               /* negate start pattern ? */
    int flush_ms;             /* default flush timeout in milliseconds */

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

    /* internal */
    struct flb_parser *parser;                 /* parser context */
    flb_sds_t parser_name;                     /* parser name for delayed init */

    /*
     * If multiline type is REGEX, it needs a set of pre-defined rules to deal
     * with messages.
     */
    struct mk_list regex_rules;

    /* Fluent Bit parent context */
    struct flb_config *config;

    /* Link node to struct flb_ml_group_parser->parsers */
    struct mk_list _head;
};

/* Multiline parser instance with running state */
struct flb_ml_parser_ins {
    struct flb_ml_parser *ml_parser;           /* multiline parser */

    /* flush callback */
    int (*cb_flush)(struct flb_ml_parser *,    /* multiline context */
                    struct flb_ml_stream *,    /* stream context */
                    void *,                    /* opaque data */
                    char *,                    /* text buffer */
                    size_t);                   /* buffer length */

    void *cb_data;                             /* opaque data */


    /*
     * Duplicate original parser definition properties for this instance. There
     * are cases where the caller wants an instance of a certain multiline
     * parser but with a custom value for key_content, key_pattern or key_group.
     */
    flb_sds_t key_content;
    flb_sds_t key_pattern;
    flb_sds_t key_group;

    /*
     * last stream_id and last_stream_group: keeping a reference of the last
     * insertion path is important to determinate when should we flush our
     * stream/stream_group buffer.
     */
    uint64_t last_stream_id;
    struct flb_ml_stream_group *last_stream_group;

    /*
     * Every multiline parser context has N streams, a stream represent a source
     * of data.
     */
    struct mk_list streams;

    /* Link to struct flb_ml_group->parsers */
    struct mk_list _head;
};

struct flb_ml_group {
    int id;                        /* group id (auto assigned) */
    struct mk_list parsers;        /* list head for parser instances */

    /* keep context of the previous match */
    struct flb_ml_parser_ins *lru_parser;

    /*
     * Flush callback for parsers instances on this group
     * --------------------------------------------------
     */
    int flush_ms;                              /* flush interval */

    /* flush callback */
    int (*cb_flush)(struct flb_ml_parser *,     /* multiline context */
                    struct flb_ml_stream *,    /* stream context */
                    void *,                    /* opaque data */
                    char *,                    /* text buffer */
                    size_t);                   /* buffer length */

    void *cb_data;                             /* opaque data */

    /* Parent multiline context */
    struct flb_ml *ml;

    struct mk_list _head;          /* link to struct flb_ml->groups list */
};

struct flb_ml {
    flb_sds_t name;                        /* name of this multiline setup */
    int flush_ms;                          /* max flush interval found in groups/parsers */
    uint64_t last_flush;                   /* last flush time (involving groups) */
    struct mk_list groups;                 /* list head for flb_ml_group(s) */
    struct flb_log_event_encoder log_event_encoder;
    struct flb_log_event_decoder log_event_decoder;
    struct flb_config *config;             /* Fluent Bit context */

    /* Limit for concatenated multiline messages */
    size_t buffer_limit;
};

struct flb_ml *flb_ml_create(struct flb_config *ctx, char *name);
int flb_ml_destroy(struct flb_ml *ml);

int flb_ml_register_context(struct flb_ml_stream_group *group,
                            struct flb_time *tm, msgpack_object *map);

int flb_ml_append_text(struct flb_ml *ml,
                  uint64_t stream_id,
                  struct flb_time *tm,
                  void *buf,
                  size_t size);

int flb_ml_append_object(struct flb_ml *ml,
                         uint64_t stream_id,
                         struct flb_time *tm,
                         msgpack_object *metadata,
                         msgpack_object *obj);

int flb_ml_append_event(struct flb_ml *ml,
                        uint64_t stream_id,
                        struct flb_log_event *event);


// int flb_ml_append_object(struct flb_ml *ml, uint64_t stream_id,
//                          struct flb_time *tm, msgpack_object *obj);

// int flb_ml_append_log_event(struct flb_ml *ml, uint64_t stream_id,
//                             struct flb_log_event *event);

int flb_ml_parsers_init(struct flb_config *ctx);

void flb_ml_flush_pending_now(struct flb_ml *ml);

void flb_ml_flush_parser_instance(struct flb_ml *ml,
                                  struct flb_ml_parser_ins *parser_i,
                                  uint64_t stream_id,
                                  int forced_flush);

int flb_ml_auto_flush_init(struct flb_ml *ml);

int flb_ml_flush_stream_group(struct flb_ml_parser *ml_parser,
                              struct flb_ml_stream *mst,
                              struct flb_ml_stream_group *group,
                              int forced_flush);

/* Multiline streams */
int flb_ml_stream_create(struct flb_ml *ml,
                         char *name,
                         int name_len,
                         int (*cb_flush) (struct flb_ml_parser *,
                                          struct flb_ml_stream *,
                                          void *cb_data,
                                          char *buf_data,
                                          size_t buf_size),
                         void *cb_data,
                         uint64_t *stream_id);

int flb_ml_stream_destroy(struct flb_ml_stream *mst);

void flb_ml_stream_id_destroy_all(struct flb_ml *ml, uint64_t stream_id);

struct flb_ml_stream *flb_ml_stream_get(struct flb_ml_parser_ins *parser,
                                        uint64_t stream_id);

struct flb_ml_stream_group *flb_ml_stream_group_get(struct flb_ml_parser_ins *ins,
                                                    struct flb_ml_stream *mst,
                                                    msgpack_object *group_name);

int flb_ml_init(struct flb_config *config);
int flb_ml_exit(struct flb_config *config);

int flb_ml_type_lookup(char *str);

int flb_ml_flush_stdout(struct flb_ml_parser *parser,
                        struct flb_ml_stream *mst,
                        void *data, char *buf_data, size_t buf_size);

#include "flb_ml_mode.h"

#endif
