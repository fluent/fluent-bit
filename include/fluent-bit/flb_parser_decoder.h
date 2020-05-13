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

#ifndef FLB_PARSER_DECODER_H
#define FLB_PARSER_DECODER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

/* Decoder behavior */
#define FLB_PARSER_DEC_DEFAULT  0  /* results place as separate keys    */
#define FLB_PARSER_DEC_AS       1  /* results replace current key/value */

/* Decoder Backend */
#define FLB_PARSER_DEC_JSON          0  /* decode_json()    */
#define FLB_PARSER_DEC_ESCAPED       1  /* decode_escaped() */
#define FLB_PARSER_DEC_ESCAPED_UTF8  2  /* decode_escaped_utf8() */
#define FLB_PARSER_DEC_MYSQL_QUOTED  3  /* decode_mysql_quoted() */

/* Decoder actions */
#define FLB_PARSER_ACT_NONE     0
#define FLB_PARSER_ACT_TRY_NEXT 1
#define FLB_PARSER_ACT_DO_NEXT  2

#define FLB_PARSER_DEC_BUF_SIZE 1024*8  /* 8KB */

struct flb_parser_dec_rule {
    int type;              /* decode_field, decode_field_as    */
    int backend;           /* backend handler: json, escaped   */
    int action;            /* actions: try_next, do_next       */

    /* Link to flb_parser_dec->rules list head */
    struct mk_list _head;
};

struct flb_parser_dec {
    flb_sds_t key;
    flb_sds_t buffer;        /* temporal buffer for decoding work */
    int add_extra_keys;      /* if type == FLB_PARSER_DEC_DEFAULT, flag is True */
    struct mk_list rules;    /* list head for decoder key rules */
    struct mk_list _head;    /* link to parser->decoders */
};

struct mk_list *flb_parser_decoder_list_create(struct mk_rconf_section *section);
int flb_parser_decoder_list_destroy(struct mk_list *list);
int flb_parser_decoder_do(struct mk_list *decoders,
                          const char *in_buf, size_t in_size,
                          char **out_buf, size_t *out_size);

#endif
