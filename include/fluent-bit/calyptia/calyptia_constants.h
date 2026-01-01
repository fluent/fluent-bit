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
#ifndef FLB_CALYPTIA_CONSTANTS_H
#define FLB_CALYPTIA_CONSTANTS_H

/* End point */
#define DEFAULT_CALYPTIA_HOST     "cloud-api.calyptia.com"
#define DEFAULT_CALYPTIA_PORT     "443"

/* HTTP action types */
#define CALYPTIA_ACTION_REGISTER  0
#define CALYPTIA_ACTION_PATCH     1
#define CALYPTIA_ACTION_METRICS   2
#define CALYPTIA_ACTION_TRACE     3

/* Endpoints */
#define CALYPTIA_ENDPOINT_CREATE  "/v1/agents"
#define CALYPTIA_ENDPOINT_PATCH   "/v1/agents/%s"
#define CALYPTIA_ENDPOINT_METRICS "/v1/agents/%s/metrics"
#define CALYPTIA_ENDPOINT_TRACE   "/v1/traces/%s"

#define CALYPTIA_ENDPOINT_FLEETS "/v1/fleets"
#define CALYPTIA_ENDPOINT_FLEET_CONFIG_INI "/v1/fleets/%s/config?format=ini&config_format=ini"
#define CALYPTIA_ENDPOINT_FLEET_CONFIG_YAML "/v1/fleets/%s/config?format=yaml&config_format=yaml"
#define CALYPTIA_ENDPOINT_FLEET_FILES "/v1/fleets/%s/files"
#define CALYPTIA_ENDPOINT_FLEET_BY_NAME "/v1/search?project_id=%s&resource=fleet&term=%s&exact=true"

/* Storage */
#define CALYPTIA_SESSION_FILE     "session.CALYPTIA"

/* Headers */
#define CALYPTIA_HEADERS_PROJECT       "X-Project-Token"
#define CALYPTIA_HEADERS_AGENT_TOKEN   "X-Agent-Token"
#define CALYPTIA_HEADERS_CTYPE         "Content-Type"
#define CALYPTIA_HEADERS_CTYPE_JSON    "application/json"
#define CALYPTIA_HEADERS_CTYPE_MSGPACK "application/x-msgpack"

#ifndef FLB_SYSTEM_WINDOWS
#define FLEET_DEFAULT_CONFIG_DIR "/tmp/calyptia-fleet"
#else
#define FLEET_DEFAULT_CONFIG_DIR NULL
#endif

#ifndef PATH_SEPARATOR
#ifndef FLB_SYSTEM_WINDOWS
#define PATH_SEPARATOR "/"
#else
#define PATH_SEPARATOR "\\"
#endif
#endif /* PATH_SEPARATOR */

#define CALYPTIA_MAX_DIR_SIZE 4096

#endif /* FLB_CALYPTIA_CONSTANTS_H */
