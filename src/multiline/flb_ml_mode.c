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
