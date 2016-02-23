/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_router.h>

/* Associate and input and output instances due to a previous match */
static int flb_router_connect(struct flb_input_instance *in,
                              struct flb_output_instance *out)
{
    struct flb_router_path *p;

    p = malloc(sizeof(struct flb_router_path));
    if (!p) {
        perror("malloc");
        return -1;
    }

    p->ins = out;
    mk_list_add(&p->_head, &in->routes);

    return 0;
}

/*
 * This routine defines static routes for the plugins that have registered
 * tags. It check where data should go before the service start running, each
 * input 'instance' plugin will contain a list of destinations.
 */
int flb_router_io_set(struct flb_config *config)
{
    struct mk_list *i_head;
    struct mk_list *o_head;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    /* Iterate all input instances */
    mk_list_foreach(i_head, &config->inputs) {
        i_ins = mk_list_entry(i_head, struct flb_input_instance, _head);
        if (!i_ins->tag) {
            continue;
        }

        /* Try to find a match with output instances */
        mk_list_foreach(o_head, &config->outputs) {
            o_ins = mk_list_entry(o_head, struct flb_output_instance, _head);

            /* FIXME: no wildcards support 'yet' */
            if (strcmp(i_ins->tag, o_ins->match) == 0) {
                flb_router_connect(i_ins, o_ins);
            }
        }
    }

    return 0;
}

void flb_router_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *r_tmp;
    struct mk_list *head;
    struct mk_list *r_head;
    struct flb_input_instance *in;
    struct flb_router_path *r;

    /* Iterate input plugins */
    mk_list_foreach_safe(head, tmp, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);

        /* Iterate instance routes */
        mk_list_foreach_safe(r_head, r_tmp, &in->routes) {
            r = mk_list_entry(r_head, struct flb_router_path, _head);
            mk_list_del(&r->_head);
            free(r);
        }
    }
}
