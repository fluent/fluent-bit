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

static void rule_error(struct flb_ml_parser *mlp)
{
    int id;

    id = mk_list_size(&mlp->regex_rules);
    flb_error("[multiline: ruby] rule #%i could not be created", id);
    flb_ml_parser_destroy(mlp);
}

/* Ruby mode */
struct flb_ml_parser *flb_ml_parser_ruby(struct flb_config *config, char *key)
{
    int ret;
    struct flb_ml_parser *mlp;

    mlp = flb_ml_parser_create(config,               /* Fluent Bit context */
                               "ruby",                 /* name      */
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
        flb_error("[multiline] could not create 'ruby mode'");
        return NULL;
    }

    ret = rule(mlp,
               "start_state, ruby_start_exception",
               "/^.+:\\d+:in\\s+.*/",
               "ruby_after_exception", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }

    ret = rule(mlp,
               "ruby_after_exception, ruby",
               "/^\\s+from\\s+.*:\\d+:in\\s+.*/",
               "ruby", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }


    /* Map the rules (mandatory for regex rules) */
    ret = flb_ml_parser_init(mlp);
    if (ret != 0) {
        flb_error("[multiline: ruby] error on mapping rules");
        flb_ml_parser_destroy(mlp);
        return NULL;
    }

    return mlp;
}
