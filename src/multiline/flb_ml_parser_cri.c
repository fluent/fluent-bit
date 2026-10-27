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
#include <fluent-bit/multiline/flb_ml_parser.h>

#define FLB_ML_CRI_TIME                         \
  "%Y-%m-%dT%H:%M:%S.%L%z"

/* Creates a parser for CRI */
static struct flb_parser *cri_parser_create(struct flb_config *config)
{
    struct flb_parser *p;

    p = flb_parser_create("_ml_cri",               /* parser name */
                          "cri",                   /* backend type */
                          NULL,                    /* regex */
                          FLB_FALSE,               /* skip_empty */
                          FLB_ML_CRI_TIME,         /* time format */
                          "time",                  /* time key */
                          NULL,                    /* time offset */
                          FLB_TRUE,                /* time keep */
                          FLB_FALSE,               /* time strict */
                          FLB_FALSE,               /* time system timezone */
                          FLB_FALSE,               /* no bare keys */
                          NULL,                    /* parser types */
                          0,                       /* types len */
                          NULL,                    /* decoders */
                          config);                 /* Fluent Bit context */
    return p;
}

struct flb_ml_parser *flb_ml_parser_cri(struct flb_config *config)
{
    struct flb_parser *parser;
    struct flb_ml_parser *mlp;

    /* Create a CRI parser */
    parser = cri_parser_create(config);
    if (!parser) {
        return NULL;
    }

    mlp = flb_ml_parser_create(config,
                               "cri",                /* name      */
                               FLB_ML_EQ,            /* type      */
                               "F",                  /* match_str */
                               FLB_FALSE,            /* negate    */
                               FLB_ML_FLUSH_TIMEOUT, /* flush_ms  */
                               "log",                /* key_content */
                               "stream",             /* key_group   */
                               "_p",                 /* key_pattern */
                               parser,               /* parser ctx  */
                               NULL);                /* parser name */

    if (!mlp) {
        flb_error("[multiline] could not create 'cri mode'");
        return NULL;
    }

    return mlp;
}
