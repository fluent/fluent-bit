/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_TESTS_INITALIZE_TLS_H
#define FLB_TESTS_INITALIZE_TLS_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_mem.h>

struct flb_config *test_env_config = NULL;

static inline void flb_test_env_config_init(void)
{
    test_env_config = flb_config_init();

    if (test_env_config == NULL) {
        return;
    }
}

static inline void flb_test_env_config_destroy(void) {
    if (test_env_config != NULL) {
        flb_config_exit(test_env_config);
    }
}

#endif
