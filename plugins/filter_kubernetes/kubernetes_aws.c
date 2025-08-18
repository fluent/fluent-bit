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


#include <sys/stat.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_jsmn.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "fluent-bit/flb_http_client.h"
#include "fluent-bit/flb_output_plugin.h"
#include "fluent-bit/flb_pack.h"
#include "fluent-bit/flb_upstream_conn.h"
/*
 * If a file exists called service.map, load it and use it.
 * If not, fall back to API. This is primarily for unit tests purposes,
 */
static int get_pod_service_file_info(struct flb_kube *ctx, char **buffer)
{
    int fd = -1;
    char *payload = NULL;
    size_t payload_size = 0;
    struct stat sb;
    int packed = -1;
    int ret;
    char uri[1024];

    if (ctx->pod_service_preload_cache_path) {

        ret = snprintf(uri, sizeof(uri) - 1, "%s.map",
                       ctx->pod_service_preload_cache_path);
        if (ret > 0) {
            fd = open(uri, O_RDONLY, 0);
            if (fd != -1) {
                if (fstat(fd, &sb) == 0) {
                    payload = flb_malloc(sb.st_size);
                    if (!payload) {
                        flb_errno();
                    }
                    else {
                        ret = read(fd, payload, sb.st_size);
                        if (ret == sb.st_size) {
                            payload_size = ret;
                        }
                    }
                }
                close(fd);
            }
        }

        if (payload_size) {
            *buffer=payload;
            packed = payload_size;
            flb_plg_debug(ctx->ins, "pod to service map content is: %s", buffer);
        }
    }

    return packed;
}

static void parse_pod_service_map(struct flb_kube *ctx, char *api_buf,
                                  size_t api_size, pthread_mutex_t *mutex)
{
    if (ctx->hash_table == NULL || ctx->pod_hash_table == NULL) {
        return;
    }
    flb_plg_debug(ctx->ins, "started parsing pod to service map");

    size_t off = 0;
    int ret;
    msgpack_unpacked api_result;
    msgpack_object api_map;
    msgpack_object k, v, attributeKey, attributeValue;
    char *buffer = NULL;
    size_t size;
    int root_type;
    int i, j;

    /* Iterate API server msgpack and lookup specific fields */
    if (api_buf != NULL) {
        ret = flb_pack_json(api_buf, api_size,
                        &buffer, &size, &root_type, NULL);

        if (ret < 0) {
            flb_plg_warn(ctx->ins, "Could not parse json response = %s",
                     api_buf);
            if (buffer) {
                flb_free(buffer);
            }
            return;
        }
        msgpack_unpacked_init(&api_result);
        ret = msgpack_unpack_next(&api_result, buffer, size, &off);
        if (ret == MSGPACK_UNPACK_SUCCESS) {
            api_map = api_result.data;
            for (i = 0; i < api_map.via.map.size; i++) {
                k = api_map.via.map.ptr[i].key;
                v = api_map.via.map.ptr[i].val;
                if (k.type == MSGPACK_OBJECT_STR && v.type == MSGPACK_OBJECT_MAP) {
                    char *pod_name = flb_strndup(k.via.str.ptr, k.via.str.size);
                    struct service_attributes *service_attributes = flb_calloc(1, sizeof(struct service_attributes));
                    for (j = 0; j < v.via.map.size; j++) {
                        attributeKey = v.via.map.ptr[j].key;
                        attributeValue = v.via.map.ptr[j].val;
                        if (attributeKey.type == MSGPACK_OBJECT_STR && attributeValue.type == MSGPACK_OBJECT_STR) {
                            char *attributeKeyString = flb_strndup(attributeKey.via.str.ptr, attributeKey.via.str.size);
                            if (strcmp(attributeKeyString, "ServiceName") == 0 &&
                                      attributeValue.via.str.size < KEY_ATTRIBUTES_MAX_LEN) {
                                strncpy(service_attributes->name, attributeValue.via.str.ptr, attributeValue.via.str.size);
                                service_attributes->name[attributeValue.via.str.size] = '\0';
                                service_attributes->name_len = attributeValue.via.str.size;
                                service_attributes->fields++;
                            }
                            if (strcmp(attributeKeyString, "Environment") == 0 &&
                                      attributeValue.via.str.size < KEY_ATTRIBUTES_MAX_LEN) {
                                strncpy(service_attributes->environment, attributeValue.via.str.ptr,attributeValue.via.str.size);
                                service_attributes->environment[attributeValue.via.str.size] = '\0';
                                service_attributes->environment_len = attributeValue.via.str.size;
                                service_attributes->fields++;
                            }
                            if (strcmp(attributeKeyString, "ServiceNameSource") == 0 &&
                                      attributeValue.via.str.size < SERVICE_NAME_SOURCE_MAX_LEN) {
                                strncpy(service_attributes->name_source, attributeValue.via.str.ptr,attributeValue.via.str.size);
                                service_attributes->name_source[attributeValue.via.str.size] = '\0';
                                service_attributes->name_source_len = attributeValue.via.str.size;
                                service_attributes->fields++;
                            }
                            flb_free(attributeKeyString);
                        }
                    }
                    if (service_attributes->name[0] != '\0' || service_attributes->environment[0] != '\0') {
                        pthread_mutex_lock(mutex);
                        flb_hash_table_add(ctx->pod_hash_table,
                                           pod_name, k.via.str.size,
                                           service_attributes, sizeof(struct service_attributes));
                        flb_free(service_attributes);
                        pthread_mutex_unlock(mutex);
                    }
                    else {
                        flb_free(service_attributes);
                    }
                    flb_free(pod_name);
                }
                else {
                    flb_plg_error(ctx->ins, "key and values are not string and map");
                }
            }
        }
    }

    flb_plg_debug(ctx->ins, "ended parsing pod to service map" );

    msgpack_unpacked_destroy(&api_result);
    if (buffer) {
        flb_free(buffer);
    }
}

int fetch_pod_service_map(struct flb_kube *ctx, char *api_server_url,
                          pthread_mutex_t *mutex)
{
    if (!ctx->use_pod_association) {
        return -1;
    }
    int ret;
    struct flb_http_client *c;
    size_t b_sent;
    struct flb_upstream_conn *u_conn;
    char *buffer = {0};

    flb_plg_debug(ctx->ins, "fetch pod to service map");

    ret = get_pod_service_file_info(ctx, &buffer);
    if (ret > 0 && buffer != NULL) {
        parse_pod_service_map(ctx, buffer, ret, mutex);
        flb_free(buffer);
    }
    else {
        /*
         * if block handles the TLS certificates update, as the Fluent-bit connection
         * gets net timeout error, it destroys the upstream. On the next call to
         * fetch_pod_service_map, it creates a new pod association upstream with
         * latest TLS certs
         */
        if (!ctx->pod_association_upstream) {
            flb_plg_debug(ctx->ins, "[kubernetes] upstream object for pod association"
                                    " is NULL. Making a new one now");
            ret = flb_kube_pod_association_init(ctx,ctx->config);
            if (ret == -1) {
                return -1;
            }
        }

        u_conn = flb_upstream_conn_get(ctx->pod_association_upstream);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "[kubernetes] no upstream connections available to %s:%i",
                          ctx->pod_association_upstream->tcp_host,
                          ctx->pod_association_upstream->tcp_port);
            flb_upstream_destroy(ctx->pod_association_upstream);
            flb_tls_destroy(ctx->pod_association_tls);
            ctx->pod_association_upstream = NULL;
            ctx->pod_association_tls = NULL;
            return -1;
        }

        /* Create HTTP client */
        c = flb_http_client(u_conn, FLB_HTTP_GET,
                            api_server_url,
                            NULL, 0, ctx->pod_association_host,
                            ctx->pod_association_port, NULL, 0);

        if (!c) {
            flb_error("[kubernetes] could not create HTTP client");
            flb_upstream_conn_release(u_conn);
            flb_upstream_destroy(ctx->pod_association_upstream);
            flb_tls_destroy(ctx->pod_association_tls);
            ctx->pod_association_upstream = NULL;
            ctx->pod_association_tls = NULL;
            return -1;
        }

        /* Perform HTTP request */
        ret = flb_http_do(c, &b_sent);
        flb_plg_debug(ctx->ins, "Request (uri = %s) http_do=%i, "
                      "HTTP Status: %i",
                      api_server_url, ret, c->resp.status);

        if (ret != 0 || c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_plg_debug(ctx->ins, "HTTP response : %s",
                              c->resp.payload);
            }
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            return -1;
        }

        /* Parse response data */
        if (c->resp.payload != NULL) {
            flb_plg_debug(ctx->ins, "HTTP response payload : %s",
                                  c->resp.payload);
            parse_pod_service_map(ctx, c->resp.payload, c->resp.payload_size, mutex);
        }

        /* Cleanup */
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
    }
    return 0;
}

/* Determine platform: check aws-auth configmap first, then JWT token */
int determine_platform(struct flb_kube *ctx)
{
    int ret;
    char *config_buf;
    size_t config_size;

    ret = get_api_server_configmap(ctx, KUBE_SYSTEM_NAMESPACE, AWS_AUTH_CONFIG_MAP, &config_buf, &config_size);
    if (ret != -1) {
        flb_free(config_buf);
        return 1;
    }
    return -1;
}

/* Gather pods list information from Kubelet */
void get_cluster_from_environment(struct flb_kube *ctx, struct flb_kube_meta *meta)
{
    if (meta->cluster == NULL) {
        char* cluster_name = getenv("CLUSTER_NAME");
        if (cluster_name) {
            meta->cluster = strdup(cluster_name);
            meta->cluster_len = strlen(cluster_name);
            meta->fields++;
        }
        flb_plg_debug(ctx->ins, "Cluster name is %s.", meta->cluster);
    }
}
