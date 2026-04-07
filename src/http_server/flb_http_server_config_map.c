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

#include <fluent-bit/http_server/flb_http_server_config_map.h>

#include <string.h>

struct flb_config_map flb_http_server_config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "http_server.http2", "true",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, http2),
     "Enable HTTP/2 support for the HTTP server"
    },
    {
     FLB_CONFIG_MAP_SIZE, "http_server.buffer_max_size", "4M",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, buffer_max_size),
     "Set the maximum size of the HTTP request buffer"
    },
    {
     FLB_CONFIG_MAP_SIZE, "http_server.buffer_chunk_size", "512K",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, buffer_chunk_size),
     "Set the buffer chunk size used for HTTP requests"
    },
    {
     FLB_CONFIG_MAP_SIZE, "http_server.max_connections", "0",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, max_connections),
     "Set the maximum number of concurrent active HTTP connections. 0 means unlimited."
    },
    {
     FLB_CONFIG_MAP_INT, "http_server.workers", "1",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, workers),
     "Set the number of HTTP listener workers"
    },
    {
     FLB_CONFIG_MAP_BOOL, "http2", "true",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, http2),
     "Compatibility alias for http_server.http2"
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", "4M",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, buffer_max_size),
     "Compatibility alias for http_server.buffer_max_size"
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", "512K",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, buffer_chunk_size),
     "Compatibility alias for http_server.buffer_chunk_size"
    },
    {
     FLB_CONFIG_MAP_SIZE, "max_connections", "0",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, max_connections),
     "Compatibility alias for http_server.max_connections"
    },
    {
     FLB_CONFIG_MAP_INT, "workers", "1",
     0, FLB_TRUE, offsetof(struct flb_http_server_config, workers),
     "Compatibility alias for http_server.workers"
    },
    {0}
};

struct mk_list *flb_http_server_get_config_map(struct flb_config *config)
{
    return flb_config_map_create(config, flb_http_server_config_map);
}

int flb_http_server_config_map_set(struct flb_config *config,
                                   struct mk_list *properties,
                                   struct mk_list *config_map,
                                   struct flb_http_server_config *context)
{
    return flb_config_map_set(config, properties, config_map, context);
}

int flb_http_server_property_is_allowed(const char *property_name)
{
    if (property_name == NULL) {
        return FLB_FALSE;
    }

    if (strncasecmp("http_server.", property_name, 12) == 0) {
        return FLB_TRUE;
    }

    if (strcasecmp("http2", property_name) == 0 ||
        strcasecmp("buffer_max_size", property_name) == 0 ||
        strcasecmp("buffer_chunk_size", property_name) == 0 ||
        strcasecmp("max_connections", property_name) == 0 ||
        strcasecmp("workers", property_name) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}
