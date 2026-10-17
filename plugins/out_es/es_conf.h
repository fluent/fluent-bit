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

#ifndef FLB_OUT_ES_CONF_H
#define FLB_OUT_ES_CONF_H

struct flb_config;
struct flb_output_instance;
struct flb_upstream_node;
struct flb_elasticsearch;
struct flb_elasticsearch_config;

#define FLB_ES_WRITE_OP_INDEX  "index"
#define FLB_ES_WRITE_OP_CREATE "create"
#define FLB_ES_WRITE_OP_UPDATE "update"
#define FLB_ES_WRITE_OP_UPSERT "upsert"

struct flb_elasticsearch *flb_es_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config);

void flb_es_conf_destroy(struct flb_elasticsearch *ctx);

struct flb_elasticsearch_config *flb_es_upstream_conf(struct flb_elasticsearch *ctx,
                                                      struct flb_upstream_node *node);

#endif
