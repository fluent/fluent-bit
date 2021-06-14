/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/multiline/flb_ml.h>

#define rule flb_ml_rule_create

static void rule_error(struct flb_ml *ml)
{
    int id;

    id = mk_list_size(&ml->regex_rules);
    flb_error("[multiline: python] rule #%i could not be created", id);
    flb_ml_destroy(ml);
}

/* Our first multiline mode: 'docker' */
struct flb_ml *flb_ml_mode_python(struct flb_config *config,
                                  int flush_ms,
                                  char *key)
{
    int ret;
    struct flb_ml *ml;

    ml = flb_ml_create(config,          /* Fluent Bit context */
                       "python",        /* name      */
                       FLB_ML_REGEX,    /* type      */
                       NULL,            /* match_str */
                       FLB_FALSE,       /* negate    */
                       flush_ms,        /* flush_ms  */
                       key,             /* key_content */
                       NULL,            /* key_group   */
                       NULL,            /* key_pattern */
                       NULL,            /* parser ctx  */
                       NULL);           /* parser name */

    if (!ml) {
        flb_error("[multiline] could not create 'python mode'");
        return NULL;
    }

    /* rule(:start_state, /^Traceback \(most recent call last\):$/, :python) */
    ret = rule(ml,
               "start_state", "/^Traceback \\(most recent call last\\):$/",
               "python", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    /* rule(:python, /^[\t ]+File /, :python_code) */
    ret = rule(ml, "python", "/^[\\t ]+File /", "python_code", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    /* rule(:python_code, /[^\t ]/, :python) */
    ret = rule(ml, "python_code", "/[^\\t ]/", "python", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    /* rule(:python, /^(?:[^\s.():]+\.)*[^\s.():]+:/, :start_state) */
    ret = rule(ml, "python", "/^(?:[^\\s.():]+\\.)*[^\\s.():]+:/", "start_state", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    /* Map the rules (mandatory for regex rules) */
    ret = flb_ml_init(ml);
    if (ret != 0) {
        flb_error("[multiline: python] error on mapping rules");
        flb_ml_destroy(ml);
        return NULL;
    }

    return ml;
}
