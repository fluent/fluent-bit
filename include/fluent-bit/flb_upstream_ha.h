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

#ifndef FLB_UPSTREAM_HA_H
#define FLB_UPSTREAM_HA_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream_node.h>
#include <monkey/mk_core.h>

struct flb_upstream_ha {
    flb_sds_t name;            /* Upstream HA name        */
    void *last_used_node;      /* Last used node          */
    struct mk_list nodes;      /* List of available nodes */
};

struct flb_upstream_ha *flb_upstream_ha_create(const char *name);
void flb_upstream_ha_destroy(struct flb_upstream_ha *ctx);
void flb_upstream_ha_node_add(struct flb_upstream_ha *ctx,
                              struct flb_upstream_node *node);
struct flb_upstream_node *flb_upstream_ha_node_get(struct flb_upstream_ha *ctx);
struct flb_upstream_ha *flb_upstream_ha_from_file(const char *file,
                                                  struct flb_config *config);

#endif
