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

#ifndef FLB_OUTPUT_H
#define FLB_OUTPUT_H

#include <fluent-bit/flb_config.h>

/* Output plugin masks */
#define FLB_OUTPUT_TCP         1  /* it uses TCP   */
#define FLB_OUTPUT_SSL         2  /* use SSL layer */
#define FLB_OUTPUT_NOPROT      4  /* do not validate protocol info */

/* Internal macros for setup */
#define FLB_OUTPUT_FLUENT      0
#define FLB_OUTPUT_HTTP        1
#define FLB_OUTPUT_HTTPS       2
#define FLB_OUTPUT_TD_HTTP     3
#define FLB_OUTPUT_TD_HTTPS    4

struct flb_output_plugin {
    int active;

    int flags;

    /* The plugin name */
    char *name;

    /* Plugin description */
    char *description;

    /* Original output address */
    char *address;

    /* Output backend address */
    int   port;
    char *host;

    /* Socket connection */
    int conn;

    /* Initalization */
    int (*cb_init)    (struct flb_config *);

    /* Pre run */
    int (*cb_pre_run) (void *, struct flb_config *);

    /* Flush callback */
    int (*cb_flush) (void *, size_t, void *, struct flb_config *);

    /* Output handler configuration */
    void *out_context;

    /* Link to global list from flb_config->outputs */
    struct mk_list _head;
};

/* Default TCP port for Fluentd */
#define FLB_OUTPUT_FLUENT_PORT  "12224"

int flb_output_set(struct flb_config *config, char *output);
void flb_output_pre_run(struct flb_config *config);
int flb_output_set_context(char *name, void *out_context, struct flb_config *config);
int flb_output_init(struct flb_config *config);

#endif
