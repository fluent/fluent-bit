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

#ifndef FLB_INPUT_H
#define FLB_INPUT_H

#include <fluent-bit/flb_config.h>

struct flb_input_plugin {
    /* Is this Input an active one ? */
    int  active;

    /* The Input name */
    char *name;

    /* Initalization */
    int (*cb_init)    (struct flb_config *);

    /*
     * Collect: every certain amount of time, Fluent Bit
     * trigger this callback.
     */
    int (*cb_collect) (void *);

    /* Input handler configuration */
    void *in_context;

    /* Link to global list from flb_config->inputs */
    struct mk_list _head;
};

struct flb_input_collector {
    int (*cb_collect) (void *);
    time_t seconds;
    time_t nanoseconds;
    struct flb_input_plugin *plugin;
    struct mk_list _head;
};

int flb_input_register_all(struct flb_config *config);
int flb_input_enable(char *name, struct flb_config *config);
int flb_input_check(struct flb_config *config);
int flb_input_set_context(char *name, void *in_context, struct flb_config *config);
int flb_input_set_collector(char *name,
                            int (*cb_collect) (void *),
                            time_t seconds,
                            long   nanoseconds,
                            struct flb_config *config);

#endif
