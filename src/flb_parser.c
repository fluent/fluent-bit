/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>


struct flb_parser_cb {
    time_t time_lookup;
    struct flb_parser *parser;
    msgpack_packer *pck;
};

struct flb_parser *flb_parser_create(char *name, char *p_regex,
                                     char *time_fmt, char *time_key,
                                     struct flb_config *config)
{
    struct flb_parser *p;
    struct flb_regex *regex;

    p = flb_calloc(1, sizeof(struct flb_parser));
    if (!p) {
        flb_errno();
        return NULL;
    }

    regex = flb_regex_create((unsigned char *) p_regex);
    if (!regex) {
        fprintf(stderr, "[parser] Invalid pattern %s\n", p_regex);
        flb_free(p);
        return NULL;
    }

    p->name = flb_strdup(name);
    p->p_regex = flb_strdup(p_regex);

    if (time_fmt) {
        p->time_fmt = flb_strdup(time_fmt);
    }
    if (time_key) {
        p->time_key = flb_strdup(time_key);
    }

    p->regex = regex;
    mk_list_add(&p->_head, &config->parsers);

    return p;
}

void flb_parser_destroy(struct flb_parser *parser)
{
    flb_regex_destroy(parser->regex);
    flb_free(parser->name);
    flb_free(parser->p_regex);

    if (parser->time_fmt) {
        flb_free(parser->time_fmt);
    }
    if (parser->time_key) {
        flb_free(parser->time_key);
    }

    mk_list_del(&parser->_head);
    flb_free(parser);
}

void flb_parser_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_parser *parser;

    mk_list_foreach_safe(head, tmp, &config->parsers) {
        parser = mk_list_entry(head, struct flb_parser, _head);
        flb_parser_destroy(parser);
    }
}

struct flb_parser *flb_parser_get(char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_parser *parser;


    mk_list_foreach(head, &config->parsers) {
        parser = mk_list_entry(head, struct flb_parser, _head);
        if (strcmp(parser->name, name) == 0) {
            return parser;
        }
    }

    return NULL;
}

static void cb_results(unsigned char *name, unsigned char *value, size_t vlen, void *data)
{
    int len;
    (void) data;
    char *time_key;
    struct flb_parser_cb *pcb = data;
    struct flb_parser *parser = pcb->parser;
    struct tm tm;

    len = strlen((char *)name);

    /* Check if there is a time lookup field */
    if (parser->time_fmt) {
        if (parser->time_key) {
            time_key = parser->time_key;
        }
        else {
            time_key = "time";
        }

        if (strcmp((char *) name, time_key) == 0) {
            if (strptime((char *) value, parser->time_fmt, &tm) != NULL) {
                pcb->time_lookup = mktime(&tm);
                return;
            }
            else {
                flb_error("[parser] Invalid time format %s", parser->time_fmt);
                return;
            }
        }
    }

    msgpack_pack_str(pcb->pck, len);
    msgpack_pack_str_body(pcb->pck, (char *) name, len);
    msgpack_pack_str(pcb->pck, vlen);
    msgpack_pack_str_body(pcb->pck, (char *) value, vlen);
}

int flb_parser_do(struct flb_parser *parser, char *buf, size_t length,
                  void **out_buf, size_t *out_size, time_t *out_time)
{
    ssize_t n;
    int arr_size;
    struct flb_regex_search result;
    struct flb_parser_cb pcb;

    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    n = flb_regex_do(parser->regex, (unsigned char *) buf, length, &result);
    if (n <= 0) {
        return -1;
    }

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    if (parser->time_fmt) {
        arr_size = (n - 1);
    }
    else {
        arr_size = n;
    }

    msgpack_pack_map(&tmp_pck, arr_size);

    /* Callback context */
    pcb.pck = &tmp_pck;
    pcb.parser = parser;
    pcb.time_lookup = 0;

    /* Iterate results and compose new buffer */
    flb_regex_parse(parser->regex, &result, cb_results, &pcb);

    /* Export results */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    *out_time = pcb.time_lookup;

    return 0;
}
