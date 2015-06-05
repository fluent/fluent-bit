/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>

#include <mk_core/mk_core.h>

#include "exec_config.h"

struct flb_in_exec_config *exec_config_init(struct mk_rconf *conf)
{
    char *command;
    long int run_interval;
    struct mk_rconf_section *section;
    struct flb_in_exec_config *config;

    section = mk_rconf_section_get(conf, "EXEC");
    if (!section) {
        return NULL;
    }

    /* command */
    command = mk_rconf_section_get_key(section, "command", MK_RCONF_STR);
    if (!command) {
        flb_utils_error_c("[EXEC] error reading command line value");
    }

    /* run_interval */
    run_interval = (long int)mk_rconf_section_get_key(section,
                                            "run_interval",
                                            MK_RCONF_NUM);
    if (run_interval <= 0) {
        flb_utils_error_c("[EXEC] error reading run_interval value");
    }

    config = malloc(sizeof(struct flb_in_exec_config));
    config->command = command;
    config->run_interval = run_interval;

    flb_debug("in_exec config: command='%s', run_interval=%d",
              config->command,
              config->run_interval);

    return config;
}

