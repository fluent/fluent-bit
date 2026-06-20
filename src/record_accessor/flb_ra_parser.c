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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

#include "ra_parser.h"
#include "ra_lex.h"

int flb_ra_parser_subkey_count(struct flb_ra_parser *rp)
{
    if (rp == NULL || rp->key == NULL) {
        return -1;
    }
    else if (rp->type != FLB_RA_PARSER_KEYMAP) {
        return 0;
    }
    else if(rp->key->subkeys == NULL) {
        return -1;
    }

    return mk_list_size(rp->key->subkeys);
}

void flb_ra_parser_dump(struct flb_ra_parser *rp)
{
    struct mk_list *head;
    struct flb_ra_key *key;
    struct flb_ra_subentry *entry;

    key = rp->key;
    if (rp->type == FLB_RA_PARSER_STRING) {
        printf("type       : STRING\n");
        printf("string     : '%s'\n", key->name);
    }
    if (rp->type == FLB_RA_PARSER_REGEX_ID) {
        printf("type       : REGEX_ID\n");
        printf("integer    : '%i'\n", rp->id);
    }
    if (rp->type == FLB_RA_PARSER_TAG) {
        printf("type       : TAG\n");
    }
    if (rp->type == FLB_RA_PARSER_TAG_PART) {
        printf("type       : TAG[%i]\n", rp->id);
    }
    else if (rp->type == FLB_RA_PARSER_KEYMAP) {
        printf("type       : KEYMAP\n");
        if (rp->key) {
            printf("key name   : %s\n", key->name);
            mk_list_foreach(head, key->subkeys) {
                entry = mk_list_entry(head, struct flb_ra_subentry, _head);
                if (entry->type == FLB_RA_PARSER_STRING) {
                    printf(" - subkey  : %s\n", entry->str);
                }
                else if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
                    printf(" - array id: %i\n", entry->array_id);
                }
            }
        }
    }
}

static void ra_parser_subentry_destroy_all(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ra_subentry *entry;

    mk_list_foreach_safe(head, tmp, list) {
        entry = mk_list_entry(head, struct flb_ra_subentry, _head);
        mk_list_del(&entry->_head);
        if (entry->type == FLB_RA_PARSER_STRING) {
            flb_sds_destroy(entry->str);
        }
        flb_free(entry);
    }
}

int flb_ra_parser_subentry_add_string(struct flb_ra_parser *rp, char *key)
{
    struct flb_ra_subentry *entry;

    entry = flb_malloc(sizeof(struct flb_ra_subentry));
    if (!entry) {
        flb_errno();
        return -1;
    }

    entry->type = FLB_RA_PARSER_STRING;
    entry->str = flb_sds_create(key);
    if (!entry->str) {
        flb_errno();
        flb_free(entry);
        return -1;
    }
    mk_list_add(&entry->_head, rp->slist);

    return 0;
}

int flb_ra_parser_subentry_add_array_id(struct flb_ra_parser *rp, int id)
{
    struct flb_ra_subentry *entry;

    entry = flb_malloc(sizeof(struct flb_ra_subentry));
    if (!entry) {
        flb_errno();
        return -1;
    }

    entry->type = FLB_RA_PARSER_ARRAY_ID;
    entry->array_id = id;
    mk_list_add(&entry->_head, rp->slist);

    return 0;
}


struct flb_ra_key *flb_ra_parser_key_add(struct flb_ra_parser *rp, char *key)
{
    struct flb_ra_key *k;

    k = flb_malloc(sizeof(struct flb_ra_key));
    if (!k) {
        flb_errno();
        return NULL;
    }

    k->name = flb_sds_create(key);
    if (!k->name) {
        flb_errno();
        flb_free(k);
        return NULL;
    }
    k->subkeys = NULL;

    return k;
}

struct flb_ra_array *flb_ra_parser_array_add(struct flb_ra_parser *rp, int index)
{
    struct flb_ra_array *arr;

    if (index < 0) {
        return NULL;
    }

    arr = flb_malloc(sizeof(struct flb_ra_array));
    if (!arr) {
        flb_errno();
        return NULL;
    }

    arr->index = index;
    arr->subkeys = NULL;

    return arr;
}

struct flb_ra_key *flb_ra_parser_string_add(struct flb_ra_parser *rp,
                                            char *str, int len)
{
    struct flb_ra_key *k;

    k = flb_malloc(sizeof(struct flb_ra_key));
    if (!k) {
        flb_errno();
        return NULL;
    }

    k->name = flb_sds_create_len(str, len);
    if (!k->name) {
        flb_errno();
        flb_free(k);
        return NULL;
    }
    k->subkeys = NULL;

    return k;
}

static struct flb_ra_parser *flb_ra_parser_create()
{
    struct flb_ra_parser *rp;

    rp = flb_calloc(1, sizeof(struct flb_ra_parser));
    if (!rp) {
        flb_errno();
        return NULL;
    }
    rp->type = -1;
    rp->key = NULL;
    rp->slist = flb_malloc(sizeof(struct mk_list));
    if (!rp->slist) {
        flb_errno();
        flb_free(rp);
        return NULL;
    }
    mk_list_init(rp->slist);

    return rp;
}

struct flb_ra_parser *flb_ra_parser_string_create(char *str, int len)
{
    struct flb_ra_parser *rp;

    rp = flb_ra_parser_create();
    if (!rp) {
        flb_error("[record accessor] could not create string context");
        return NULL;
    }

    rp->type = FLB_RA_PARSER_STRING;
    rp->key = flb_malloc(sizeof(struct flb_ra_key));
    if (!rp->key) {
        flb_errno();
        flb_ra_parser_destroy(rp);
        return NULL;
    }
    rp->key->subkeys = NULL;
    rp->key->name = flb_sds_create_len(str, len);
    if (!rp->key->name) {
        flb_ra_parser_destroy(rp);
        return NULL;
    }

    return rp;
}

struct flb_ra_parser *flb_ra_parser_regex_id_create(int id)
{
    struct flb_ra_parser *rp;

    rp = flb_ra_parser_create();
    if (!rp) {
        flb_error("[record accessor] could not create string context");
        return NULL;
    }

    rp->type = FLB_RA_PARSER_REGEX_ID;
    rp->id = id;
    return rp;
}

struct flb_ra_parser *flb_ra_parser_tag_create()
{
    struct flb_ra_parser *rp;

    rp = flb_ra_parser_create();
    if (!rp) {
        flb_error("[record accessor] could not create tag context");
        return NULL;
    }

    rp->type = FLB_RA_PARSER_TAG;
    return rp;
}

struct flb_ra_parser *flb_ra_parser_tag_part_create(int id)
{
    struct flb_ra_parser *rp;

    rp = flb_ra_parser_create();
    if (!rp) {
        flb_error("[record accessor] could not create tag context");
        return NULL;
    }

    rp->type = FLB_RA_PARSER_TAG_PART;
    rp->id = id;

    return rp;
}

struct flb_ra_parser *flb_ra_parser_meta_create(char *str, int len)
{
    int ret;
    yyscan_t scanner;
    YY_BUFFER_STATE buf;
    flb_sds_t s;
    struct flb_ra_parser *rp;
    struct flb_ra_key *key;

    rp = flb_ra_parser_create();
    if (!rp) {
        flb_error("[record accessor] could not create meta context");
        return NULL;
    }

    /* Temporal buffer of string with fixed length */
    s = flb_sds_create_len(str, len);
    if (!s) {
        flb_errno();
        flb_ra_parser_destroy(rp);
        return NULL;
    }

    /* Flex/Bison work */
    flb_ra_lex_init(&scanner);
    buf = flb_ra__scan_string(s, scanner);

    ret = flb_ra_parse(rp, s, scanner);

    /* release resources */
    flb_sds_destroy(s);
    flb_ra__delete_buffer(buf, scanner);
    flb_ra_lex_destroy(scanner);

    /* Finish structure mapping */
    if (rp->type == FLB_RA_PARSER_KEYMAP) {
        if (rp->key) {
            key = rp->key;
            key->subkeys = rp->slist;
            rp->slist = NULL;
        }
    }

    if (ret != 0) {
        flb_ra_parser_destroy(rp);
        return NULL;
    }

    return rp;
}

void flb_ra_parser_destroy(struct flb_ra_parser *rp)
{
    struct flb_ra_key *key;

    key = rp->key;
    if (key) {
        flb_sds_destroy(key->name);
        if (key->subkeys) {
            ra_parser_subentry_destroy_all(key->subkeys);
            flb_free(key->subkeys);
        }
        flb_free(rp->key);
    }
    if (rp->slist) {
        ra_parser_subentry_destroy_all(rp->slist);
        flb_free(rp->slist);
    }
    flb_free(rp);
}
