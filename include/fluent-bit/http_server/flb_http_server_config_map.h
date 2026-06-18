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

#ifndef FLB_HTTP_SERVER_CONFIG_MAP_H
#define FLB_HTTP_SERVER_CONFIG_MAP_H

#include <stddef.h>

#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/http_server/flb_http_server.h>

extern struct flb_config_map flb_http_server_config_map[];

struct mk_list *flb_http_server_get_config_map(struct flb_config *config);

int flb_http_server_property_is_allowed(const char *property_name);

int flb_http_server_config_map_set(struct flb_config *config,
                                   struct mk_list *properties,
                                   struct mk_list *config_map,
                                   struct flb_http_server_config *context);

#endif
