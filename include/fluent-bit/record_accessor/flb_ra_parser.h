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

#ifndef FLB_RA_PARSER_H
#define FLB_RA_PARSER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

#define FLB_RA_PARSER_STRING    0  /* fixed string   */
#define FLB_RA_PARSER_KEYMAP    1  /* record map key */
#define FLB_RA_PARSER_ARRAY_ID  2  /* fixed string   */
#define FLB_RA_PARSER_FUNC      3  /* record function: tag, time... */
#define FLB_RA_PARSER_REGEX_ID  4  /* regex id / capture position */
#define FLB_RA_PARSER_TAG       5  /* full tag */
#define FLB_RA_PARSER_TAG_PART  6  /* tag part */

struct flb_ra_subentry {
    int type;    /* string = FLB_RA_PARSER_STRING | array id = FLB_RA_PARSER_ARRAY_ID */
    union {
        int array_id;
        flb_sds_t str;
    };
    struct mk_list _head;
};

struct flb_ra_array {
    int index;
    struct mk_list *subkeys;
};

struct flb_ra_key {
    flb_sds_t name;
    struct mk_list *subkeys;
};

struct flb_ra_parser {
    int type;                /* token type */
    int id;                  /* used by PARSER_REGEX_ID & PARSER_TAG_PART */
    struct flb_ra_key *key;  /* context of data type */
    struct mk_list *slist;   /* temporary list for subkeys parsing */
    struct mk_list _head;    /* link to parent flb_record_accessor->list */
};

struct flb_ra_key *flb_ra_parser_key_add(struct flb_ra_parser *ra, char *key);

int flb_ra_parser_subentry_add_string(struct flb_ra_parser *rp, char *key);
int flb_ra_parser_subentry_add_array_id(struct flb_ra_parser *rp, int id);

int flb_ra_parser_subkey_count(struct flb_ra_parser *rp);
void flb_ra_parser_dump(struct flb_ra_parser *rp);
struct flb_ra_parser *flb_ra_parser_string_create(char *str, int len);
struct flb_ra_parser *flb_ra_parser_regex_id_create(int id);
struct flb_ra_parser *flb_ra_parser_meta_create(char *str, int len);
struct flb_ra_parser *flb_ra_parser_tag_create();
struct flb_ra_parser *flb_ra_parser_tag_part_create(int id);
void flb_ra_parser_destroy(struct flb_ra_parser *rp);

#endif
