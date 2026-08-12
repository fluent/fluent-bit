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
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_rule.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#define rule flb_ml_rule_create

static void rule_error(struct flb_ml_parser *ml_parser)
{
    int id;

    id = mk_list_size(&ml_parser->regex_rules);
    flb_error("[multiline: json] rule #%i could not be created", id);
    flb_ml_parser_destroy(ml_parser);
}

/*
 * Built-in multiline mode for pretty-printed JSON objects.
 *
 * Tail reads line-by-line, so a formatted JSON object is not valid JSON per
 * line. This parser groups lines from an opening '{' until the next object
 * starts or flush_timeout expires.
 *
 * Do not attach a JSON parser here: per-line JSON parsing fails on partial
 * lines (see ml_append_try_parser_type_text). Use filter_parser on the
 * assembled 'log' field after grouping.
 */
struct flb_ml_parser *flb_ml_parser_json(struct flb_config *config, char *key)
{
    int ret;
    struct flb_ml_parser *mlp;

    mlp = flb_ml_parser_create(config,               /* Fluent Bit context */
                               "json",               /* name      */
                               FLB_ML_REGEX,         /* type      */
                               NULL,                 /* match_str */
                               FLB_FALSE,            /* negate    */
                               FLB_ML_FLUSH_TIMEOUT, /* flush_ms  */
                               key,                  /* key_content */
                               NULL,                 /* key_group   */
                               NULL,                 /* key_pattern */
                               NULL,                 /* parser ctx  */
                               NULL);                /* parser name */

    if (!mlp) {
        flb_error("[multiline] could not create 'json mode'");
        return NULL;
    }

    ret = rule(mlp,
               "start_state",
               "/^\\{.*/",
               "cont", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }

    ret = rule(mlp,
               "cont",
               "/^([^\\S\\r\\n].*|})$/",
               "cont", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }

    ret = flb_ml_parser_init(mlp);
    if (ret != 0) {
        flb_error("[multiline: json] error on mapping rules");
        flb_ml_parser_destroy(mlp);
        return NULL;
    }

    return mlp;
}
