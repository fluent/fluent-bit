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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>

struct flb_parser *flb_parser_create(char *name, char *p_regex, char *p_time,
                                     struct flb_config *config)
{
    struct flb_parser *p;
    struct flb_regex *regex;

    p = flb_malloc(sizeof(struct flb_parser));
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

    if (p_time) {
        p->p_time = flb_strdup(p_time);
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
    if (parser->p_time) {
        flb_free(parser->p_time);
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
    msgpack_packer *pck = data;

    len = strlen((char *)name);

    msgpack_pack_str(pck, len);
    msgpack_pack_str_body(pck, (char *) name, len);
    msgpack_pack_str(pck, vlen);
    msgpack_pack_str_body(pck, (char *) value, vlen);
}

int flb_parser_do(struct flb_parser *parser, char *buf, size_t length,
                  void **out_buf, size_t *out_size)
{
    ssize_t n;
    struct flb_regex_search result;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    n = flb_regex_do(parser->regex, (unsigned char *) buf, length, &result);
    if (n <= 0) {
        return -1;
    }

    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&tmp_pck, n);
    flb_regex_parse(parser->regex, &result, cb_results, &tmp_pck);

    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return 0;
}
