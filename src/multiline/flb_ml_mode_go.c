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
    flb_error("[multiline: go] rule #%i could not be created", id);
    flb_ml_destroy(ml);
}

/* Golang mode */
struct flb_ml *flb_ml_mode_go(struct flb_config *config, int flush_ms,
                              char *key)
{
    int ret;
    struct flb_ml *ml;

    ml = flb_ml_create(config,          /* Fluent Bit context */
                       FLB_ML_REGEX,    /* type      */
                       NULL,            /* match_str */
                       FLB_FALSE,       /* negate    */
                       flush_ms,        /* flush_ms  */
                       key,             /* key_content */
                       NULL,            /* key_pattern */
                       NULL);           /* parser */

    if (!ml) {
        flb_error("[multiline] could not create 'python mode'");
        return NULL;
    }

    ret = rule(ml,
               "start_state",
               "/\\bpanic: /",
               "go_after_panic", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "start_state",
               "/http: panic serving/",
               "go_goroutine", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "go_after_panic",
               "/^$/",
               "go_goroutine", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "go_after_panic, go_after_signal, go_frame_1",
               "/^$/",
               "go_goroutine", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "go_after_panic",
               "/^\\[signal /",
               "go_after_signal", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "go_goroutine",
               "/^goroutine \\d+ \\[[^\\]]+\\]:$/",
               "go_frame_1", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "go_frame_1",
               "/^(?:[^\\s.:]+\\.)*[^\\s.():]+\\(|^created by /",
               "go_frame_2", NULL);
    if (ret != 0) {
        rule_error(ml);
        return NULL;
    }

    ret = rule(ml,
               "go_frame_2",
               "/^\\s/",
               "go_frame_1", NULL);
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
