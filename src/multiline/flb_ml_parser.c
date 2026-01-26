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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <fluent-bit/multiline/flb_ml_group.h>

#include <stddef.h>
#include <string.h>

/* ---------------- params + defaults ---------------- */
struct flb_ml_parser_params flb_ml_parser_params_default(const char *name)
{
    struct flb_ml_parser_params p;
    memset(&p, 0, sizeof(p));

    p.size      = sizeof(p);
    p.name      = (char *) name;
    p.type      = FLB_ML_REGEX;          /* sane default */
    p.negate    = 0;
    p.flush_ms  = FLB_ML_FLUSH_TIMEOUT;  /* header constant */
    /* other pointers remain NULL by default */
    return p;
}

/* New canonical creator that mirrors old behavior using params */
struct flb_ml_parser *flb_ml_parser_create_params(struct flb_config *ctx,
                                                  const struct flb_ml_parser_params *p)
{
    struct flb_ml_parser *ml_parser;
    size_t min = offsetof(struct flb_ml_parser_params, flags) + sizeof(uint32_t);

    if (!ctx || !p || p->size < min || !p->name) {
        return NULL;
    }

    ml_parser = flb_calloc(1, sizeof(struct flb_ml_parser));
    if (!ml_parser) {
        flb_errno();
        return NULL;
    }

    /* prepare rules list */
    mk_list_init(&ml_parser->_head);
    mk_list_init(&ml_parser->regex_rules);

    /* name/type */
    ml_parser->name = flb_sds_create(p->name);
    if (!ml_parser->name) {
        flb_ml_parser_destroy(ml_parser);
        return NULL;
    }
    ml_parser->type = p->type;

    /* ENDSWITH/EQ optimization string */
    if (p->match_str) {
        ml_parser->match_str = flb_sds_create(p->match_str);
        if (!ml_parser->match_str) {
            flb_ml_parser_destroy(ml_parser);
            return NULL;
        }
    }

    /* sub-parser (immediate / delayed) */
    ml_parser->parser = p->parser_ctx;
    if (p->parser_name) {
        ml_parser->parser_name = flb_sds_create(p->parser_name);
        if (!ml_parser->parser_name) {
            flb_ml_parser_destroy(ml_parser);
            return NULL;
        }
    }

    /* basic props */
    ml_parser->negate   = p->negate;
    ml_parser->flush_ms = (p->flush_ms > 0) ? p->flush_ms : FLB_ML_FLUSH_TIMEOUT;


    /* optional keys */
    if (p->key_content) {
        ml_parser->key_content = flb_sds_create(p->key_content);
        if (!ml_parser->key_content) {
            flb_ml_parser_destroy(ml_parser);
            return NULL;
        }
    }
    if (p->key_group) {
        ml_parser->key_group = flb_sds_create(p->key_group);
        if (!ml_parser->key_group) {
            flb_ml_parser_destroy(ml_parser);
            return NULL;
        }
    }
    if (p->key_pattern) {
        ml_parser->key_pattern = flb_sds_create(p->key_pattern);
        if (!ml_parser->key_pattern) {
            flb_ml_parser_destroy(ml_parser);
            return NULL;
        }
    }

    /* keep back-pointer to config for later rule init */
    ml_parser->config = ctx;

    /* link into registry after all initialization succeeds */
    mk_list_add(&ml_parser->_head, &ctx->multiline_parsers);

    return ml_parser;
}

int flb_ml_parser_init(struct flb_ml_parser *ml_parser)
{
    int ret;

    ret = flb_ml_rule_init(ml_parser);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

/* Create built-in multiline parsers */
int flb_ml_parser_builtin_create(struct flb_config *config)
{
    struct flb_ml_parser *mlp;
    int ret = -1;

    /* Docker */
    mlp = flb_ml_parser_docker(config);
    if (!mlp) {
        flb_error("[multiline] could not init 'docker' built-in parser");
        goto error;
    }

    /* CRI */
    mlp = flb_ml_parser_cri(config);
    if (!mlp) {
        flb_error("[multiline] could not init 'cri' built-in parser");
        goto error;
    }

    /* Java */
    mlp = flb_ml_parser_java(config, NULL);
    if (!mlp) {
        flb_error("[multiline] could not init 'java' built-in parser");
        goto error;
    }

    /* Go */
    mlp = flb_ml_parser_go(config, NULL);
    if (!mlp) {
        flb_error("[multiline] could not init 'go' built-in parser");
        goto error;
    }

    /* Ruby */
    mlp = flb_ml_parser_ruby(config, NULL);
    if (!mlp) {
        flb_error("[multiline] could not init 'ruby' built-in parser");
        goto error;
    }

    /* Python */
    mlp = flb_ml_parser_python(config, NULL);
    if (!mlp) {
        flb_error("[multiline] could not init 'python' built-in parser");
        goto error;
    }

    ret = 0;
    return ret;

error:
    flb_ml_parser_destroy_all(&config->multiline_parsers);
    return ret;
}

/* Legacy positional-args API -> thin wrapper to params */
struct flb_ml_parser *flb_ml_parser_create(struct flb_config *ctx,
                                           char *name,
                                           int type, char *match_str, int negate,
                                           int flush_ms,
                                           char *key_content,
                                           char *key_group,
                                           char *key_pattern,
                                           struct flb_parser *parser_ctx,
                                           char *parser_name)
{
    struct flb_ml_parser_params p = flb_ml_parser_params_default(name);

    /* override with legacy parameters */
    p.type        = type;
    p.match_str   = match_str;
    p.negate      = negate;
    p.flush_ms    = flush_ms;
    p.key_content = key_content;
    p.key_group   = key_group;
    p.key_pattern = key_pattern;
    p.parser_ctx  = parser_ctx;
    p.parser_name = parser_name;

    return flb_ml_parser_create_params(ctx, &p);
}

struct flb_ml_parser *flb_ml_parser_get(struct flb_config *ctx, char *name)
{
    struct mk_list *head;
    struct flb_ml_parser *ml_parser;

    mk_list_foreach(head, &ctx->multiline_parsers) {
        ml_parser = mk_list_entry(head, struct flb_ml_parser, _head);
        if (strcasecmp(ml_parser->name, name) == 0) {
            return ml_parser;
        }
    }

    return NULL;
}

int flb_ml_parser_instance_has_data(struct flb_ml_parser_ins *ins)
{
    struct mk_list *head;
    struct mk_list *head_group;
    struct flb_ml_stream *st;
    struct flb_ml_stream_group *st_group;

    mk_list_foreach(head, &ins->streams) {
        st = mk_list_entry(head, struct flb_ml_stream, _head);
        mk_list_foreach(head_group, &st->groups) {
            st_group = mk_list_entry(head_group, struct flb_ml_stream_group, _head);
            if (st_group->mp_sbuf.size > 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

struct flb_ml_parser_ins *flb_ml_parser_instance_create(struct flb_ml *ml,
                                                        char *name)
{
    int ret;
    struct flb_ml_parser_ins *ins;
    struct flb_ml_parser *parser;

    parser = flb_ml_parser_get(ml->config, name);
    if (!parser) {
        flb_error("[multiline] parser '%s' not registered", name);
        return NULL;
    }

    ins = flb_calloc(1, sizeof(struct flb_ml_parser_ins));
    if (!ins) {
        flb_errno();
        return NULL;
    }
    ins->last_stream_id = 0;
    ins->ml_parser = parser;
    mk_list_init(&ins->streams);

    /* Copy parent configuration */
    if (parser->key_content) {
        ins->key_content = flb_sds_create(parser->key_content);
    }
    if (parser->key_pattern) {
        ins->key_pattern = flb_sds_create(parser->key_pattern);
    }
    if (parser->key_group) {
        ins->key_group = flb_sds_create(parser->key_group);
    }

    /* Append this multiline parser instance to the active multiline group */
    ret = flb_ml_group_add_parser(ml, ins);
    if (ret != 0) {
        flb_error("[multiline] could not register parser '%s' on "
                  "multiline '%s 'group", name, ml->name);
        flb_free(ins);
        return NULL;
    }

    /*
     * Update flush_interval for pending records on multiline context. We always
     * use the greater value found.
     */
    if (parser->flush_ms > ml->flush_ms) {
        ml->flush_ms = parser->flush_ms;
    }

    return ins;
}

/* Override a fixed parser property for the instance only*/
int flb_ml_parser_instance_set(struct flb_ml_parser_ins *p, char *prop, char *val)
{
    if (strcasecmp(prop, "key_content") == 0) {
        if (p->key_content) {
            flb_sds_destroy(p->key_content);
        }
        p->key_content = flb_sds_create(val);
    }
    else if (strcasecmp(prop, "key_pattern") == 0) {
        if (p->key_pattern) {
            flb_sds_destroy(p->key_pattern);
        }
        p->key_pattern = flb_sds_create(val);
    }
    else if (strcasecmp(prop, "key_group") == 0) {
        if (p->key_group) {
            flb_sds_destroy(p->key_group);
        }
        p->key_group = flb_sds_create(val);
    }
    else {
        return -1;
    }

    return 0;
}

int flb_ml_parser_destroy(struct flb_ml_parser *ml_parser)
{
    if (!ml_parser) {
        return 0;
    }

    if (ml_parser->name) {
        flb_sds_destroy(ml_parser->name);
    }

    if (ml_parser->parser_name) {
        flb_sds_destroy(ml_parser->parser_name);
    }

    if (ml_parser->match_str) {
        flb_sds_destroy(ml_parser->match_str);
    }
    if (ml_parser->key_content) {
        flb_sds_destroy(ml_parser->key_content);
    }
    if (ml_parser->key_group) {
        flb_sds_destroy(ml_parser->key_group);
    }
    if (ml_parser->key_pattern) {
        flb_sds_destroy(ml_parser->key_pattern);
    }

    /* Regex rules */
    flb_ml_rule_destroy_all(ml_parser);

    /* Unlink from struct flb_config->multiline_parsers */
    mk_list_del(&ml_parser->_head);

    flb_free(ml_parser);
    return 0;
}

int flb_ml_parser_instance_destroy(struct flb_ml_parser_ins *ins)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ml_stream *stream;

    /* Destroy streams */
    mk_list_foreach_safe(head, tmp, &ins->streams) {
        stream = mk_list_entry(head, struct flb_ml_stream, _head);
        flb_ml_stream_destroy(stream);
    }

    if (ins->key_content) {
        flb_sds_destroy(ins->key_content);
    }
    if (ins->key_pattern) {
        flb_sds_destroy(ins->key_pattern);
    }
    if (ins->key_group) {
        flb_sds_destroy(ins->key_group);
    }

    flb_free(ins);

    return 0;
}

void flb_ml_parser_destroy_all(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ml_parser *parser;

    mk_list_foreach_safe(head, tmp, list) {
        parser = mk_list_entry(head, struct flb_ml_parser, _head);
        flb_ml_parser_destroy(parser);
    }
}
