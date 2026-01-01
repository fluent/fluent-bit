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
#include <fluent-bit/multiline/flb_ml_mode.h>

struct flb_ml *flb_ml_mode_create(struct flb_config *config, char *mode, int flush_ms,
                                  char *key)
{
    if (strcmp(mode, "docker") == 0) {
        return flb_ml_mode_docker(config, flush_ms);
    }
    else if (strcmp(mode, "cri") == 0) {
        return flb_ml_mode_cri(config, flush_ms);
    }
    else if (strcmp(mode, "python") == 0) {
        return flb_ml_mode_python(config, flush_ms, key);
    }
    else if (strcmp(mode, "java") == 0) {
        return flb_ml_mode_java(config, flush_ms, key);
    }
    else if (strcmp(mode, "go") == 0) {
        return flb_ml_mode_go(config, flush_ms, key);
    }

    flb_error("[multiline] built-in mode '%s' not found", mode);
    return NULL;
}


struct flb_ml_mode *flb_ml_parser_create(struct flb_config *ctx,
                                         char *name,
                                         int type, char *match_str, int negate,
                                         int flush_ms,
                                         char *key_content,
                                         char *key_group,
                                         char *key_pattern,
                                         struct flb_parser *parser_ctx,
                                         char *parser_name)
{
    struct flb_ml_mode *ml;

    ml = flb_calloc(1, sizeof(struct flb_ml));
    if (!ml) {
        flb_errno();
        return NULL;
    }
    ml->name = flb_sds_create(name);
    ml->type = type;

    if (match_str) {
        ml->match_str = flb_sds_create(match_str);
        if (!ml->match_str) {
            flb_free(ml);
            return NULL;
        }
    }

    ml->parser = parser_ctx;
    if (parser_name) {
        ml->parser_name = flb_sds_create(parser_name);
    }

    ml->negate = negate;
    mk_list_init(&ml->streams);
    mk_list_init(&ml->regex_rules);
    mk_list_add(&ml->_head, &ctx->multilines);

    if (key_content) {
        ml->key_content = flb_sds_create(key_content);
        if (!ml->key_content) {
            flb_ml_destroy(ml);
            return NULL;
        }
    }

    if (key_group) {
        ml->key_group = flb_sds_create(key_group);
        if (!ml->key_group) {
            flb_ml_destroy(ml);
            return NULL;
        }
    }

    if (key_pattern) {
        ml->key_pattern = flb_sds_create(key_pattern);
        if (!ml->key_pattern) {
            flb_ml_destroy(ml);
            return NULL;
        }
    }
    return ml;
}
