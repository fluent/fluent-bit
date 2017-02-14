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
#include <fluent-bit/flb_parser.h>

int flb_parser_regex_do(struct flb_parser *parser,
                        char *buf, size_t length,
                        void **out_buf, size_t *out_size,
                        time_t *out_time);

int flb_parser_json_do(struct flb_parser *parser,
                       char *buf, size_t length,
                       void **out_buf, size_t *out_size,
                       time_t *out_time);

struct flb_parser *flb_parser_create(char *name, char *format,
                                     char *p_regex,
                                     char *time_fmt, char *time_key,
                                     int time_keep, struct flb_config *config)
{
    struct flb_parser *p;
    struct flb_regex *regex;

    p = flb_calloc(1, sizeof(struct flb_parser));
    if (!p) {
        flb_errno();
        return NULL;
    }

    /* Format lookup */
    if (strcmp(format, "regex") == 0) {
        p->type = FLB_PARSER_REGEX;
    }
    else if (strcmp(format, "json") == 0) {
        p->type = FLB_PARSER_JSON;
    }
    else {
        fprintf(stderr, "[parser] Invalid format %s\n", format);
        flb_free(p);
        return NULL;
    }

    if (p->type == FLB_PARSER_REGEX) {
        if (!p_regex) {
            fprintf(stderr, "[parser] Invalid regex pattern\n");
            flb_free(p);
            return NULL;
        }

        regex = flb_regex_create((unsigned char *) p_regex);
        if (!regex) {
            fprintf(stderr, "[parser] Invalid regex pattern %s\n", p_regex);
            flb_free(p);
            return NULL;
        }
        p->regex = regex;
        p->p_regex = flb_strdup(p_regex);
    }

    p->name = flb_strdup(name);

    if (time_fmt) {
        p->time_fmt = flb_strdup(time_fmt);
    }
    if (time_key) {
        p->time_key = flb_strdup(time_key);
    }
    p->time_keep = time_keep;

    mk_list_add(&p->_head, &config->parsers);

    return p;
}

void flb_parser_destroy(struct flb_parser *parser)
{
    if (parser->type == FLB_PARSER_REGEX) {
        flb_regex_destroy(parser->regex);
        flb_free(parser->p_regex);
    }

    flb_free(parser->name);
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

int flb_parser_do(struct flb_parser *parser, char *buf, size_t length,
                  void **out_buf, size_t *out_size, time_t *out_time)
{

    if (parser->type == FLB_PARSER_REGEX) {
        return flb_parser_regex_do(parser, buf, length,
                                   out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_JSON) {
        return flb_parser_json_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }

    return -1;
}
