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

#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/in_kmsg.h>

static void add_input(char *name,
                      struct flb_config *config,
                      int (*init) (struct flb_config *))
{
    struct flb_input_handler *in;

    in = malloc(sizeof(struct flb_input_handler));
    in->name = strdup(name);
    in->cb_init = init;

    mk_list_add(&in->_head, &config->inputs);
}

/* Register all supported inputs */
int flb_input_register_all(struct flb_config *config)
{
    mk_list_init(&config->inputs);

    add_input("cpu" , config, NULL);
    add_input("kmsg", config, in_kmsg_start);
}

/* Enable an input */
int flb_input_enable(char *input, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_handler *handler;

    mk_list_foreach(head, &config->inputs) {
        handler = mk_list_entry(head, struct flb_input_handler, _head);
        if (strncmp(handler->name, input, strlen(input)) == 0) {
            handler->active = FLB_TRUE;
            return 0;
        }
    }

    return -1;
}
