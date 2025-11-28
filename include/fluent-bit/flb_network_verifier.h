/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_NETWORK_VERIFIER_H
#define FLB_NETWORK_VERIFIER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>

#include <openssl/types.h>

#define FLB_X509_STORE_EX_INDEX 0

struct flb_network_verifier_instance;

struct flb_network_verifier_plugin {
    char *name;            /* Name                               */
    char *description;     /* Description                        */

    /* Config map */
    struct flb_config_map *config_map;

    /* Callbacks */
    int (*cb_init) (struct flb_network_verifier_instance *, struct flb_config *);
    int (*cb_verify_tls) (int, X509_STORE_CTX *);
    int (*cb_connection_failure) (struct flb_network_verifier_instance*, const char*, int, int, const char*);
    int (*cb_exit) (void *, struct flb_config *);

    struct mk_list _head;  /* Link to parent list (config->network_verifier_plugins) */
};

/*
 * Each initialized plugin must have an instance, the same plugin may be
 * loaded more than one time.
 *
 * An instance will contain basic fixed plugin data while also
 * allowing for plugin context data, generated when the plugin is invoked.
 */
struct flb_network_verifier_instance {
    int id;                                 /* instance id              */
    int log_level;                          /* instance log level       */
    char name[32];                          /* numbered name            */
    char *alias;                            /* alias name               */
    void *context;                          /* Instance local context   */
    struct flb_network_verifier_plugin *plugin; /* original plugin   */

    struct mk_list properties;              /* config properties        */
    struct mk_list *config_map;             /* configuration map        */

    /* Keep a reference to the original context this instance belongs to */
    const struct flb_config *config;

    struct mk_list _head;                   /* config->network_verifiers  */
};

struct flb_network_verifier_instance *flb_network_verifier_new(
    struct flb_config *config, const char *name);

const char *flb_network_verifier_get_alias(
    struct flb_network_verifier_instance *ins);

int flb_network_verifier_set_property(
   struct flb_network_verifier_instance *ins, const char *k, const char *v);
int flb_network_verifier_plugin_property_check(
    struct flb_network_verifier_instance *ins,
    struct flb_config *config);
int flb_network_verifier_init_all(struct flb_config *config);
void flb_network_verifier_exit(struct flb_config *config);

void flb_network_verifier_instance_destroy(
    struct flb_network_verifier_instance *ins);

const struct flb_network_verifier_instance *find_network_verifier_instance(
                struct flb_config *config,
                const char* alias);


#endif