/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "fluent-bit/flb_http_client.h"
#include "fluent-bit/flb_filter_plugin.h"
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

    if (ctx->aws_pod_service_preload_cache_path) {

        ret = snprintf(uri, sizeof(uri) - 1, "%s.map",
                       ctx->aws_pod_service_preload_cache_path);
        if (ret > 0) {
            fd = open(uri, O_RDONLY, 0);
            if (fd == -1) {
                flb_errno();
                return -1;
            }
            if (fstat(fd, &sb) == 0) {
                payload = flb_malloc(sb.st_size);
                if (!payload) {
                    flb_errno();
                    return -1;
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

        if (payload_size) {
            *buffer=payload;
            packed = payload_size;
            flb_plg_debug(ctx->ins, "pod to service map content is: %s", *buffer);
        }
    }

    return packed;
}

static void extract_service_attribute(msgpack_object *attr_map, const char *key_name, 
                                      char *dest, int max_len, int *dest_len, int *fields)
{
    struct flb_record_accessor *ra;
    struct flb_ra_value *val;
    const char *str_val;
    size_t str_len;
    
    ra = flb_ra_create((char *)key_name, FLB_FALSE);
    if (!ra) {
        return;
    }
    
    val = flb_ra_get_value_object(ra, *attr_map);
    if (val && val->type == FLB_RA_STRING) {
        str_val = flb_ra_value_buffer(val, &str_len);
        if (str_val && str_len < max_len) {
            memcpy(dest, str_val, str_len);
            dest[str_len] = '\0';
            *dest_len = str_len;
            (*fields)++;
        }
        flb_ra_key_value_destroy(val);
    }
    flb_ra_destroy(ra);
}

static void parse_pod_service_map(struct flb_kube *ctx, char *api_buf,
                                  size_t api_size, pthread_mutex_t *mutex)
{
    if (ctx->hash_table == NULL || ctx->aws_pod_service_hash_table == NULL) {
        return;
    }
    flb_plg_debug(ctx->ins, "started parsing pod to service map");

    size_t off = 0;
    int ret;
    msgpack_unpacked api_result;
    msgpack_object api_map, k, v;
    struct service_attributes *attrs;
    char *buffer = NULL;
    size_t size;
    int root_type;
    int i;

    if (api_buf == NULL) {
        return;
    }

    ret = flb_pack_json(api_buf, api_size, &buffer, &size, &root_type, NULL);
    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Could not parse json response = %s", api_buf);
        if (buffer) {
            flb_free(buffer);
        }
        return;
    }

    msgpack_unpacked_init(&api_result);
    ret = msgpack_unpack_next(&api_result, buffer, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        goto cleanup;
    }

    api_map = api_result.data;
    for (i = 0; i < api_map.via.map.size; i++) {
        k = api_map.via.map.ptr[i].key;
        v = api_map.via.map.ptr[i].val;
        
        if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "key and values are not string and map");
            continue;
        }
        char *pod_name = flb_strndup(k.via.str.ptr, k.via.str.size);
        if (!pod_name) {
            flb_free(pod_name);
            continue;
        }
        attrs = flb_calloc(1, sizeof(struct service_attributes));
        if (!attrs) {
            flb_errno();
            flb_free(pod_name);
            continue;
        }
        extract_service_attribute(&v, "$ServiceName", attrs->name,
                                  KEY_ATTRIBUTES_MAX_LEN, &attrs->name_len, &attrs->fields);
        extract_service_attribute(&v, "$Environment", attrs->environment,
                           	      KEY_ATTRIBUTES_MAX_LEN, &attrs->environment_len, &attrs->fields);
        extract_service_attribute(&v, "$ServiceNameSource", attrs->name_source, 
                                  SERVICE_NAME_SOURCE_MAX_LEN, &attrs->name_source_len, &attrs->fields);
        if (attrs->name[0] != '\0' || attrs->environment[0] != '\0') {
            pthread_mutex_lock(mutex);
            flb_hash_table_add(ctx->aws_pod_service_hash_table, pod_name, k.via.str.size,
                               attrs, sizeof(struct service_attributes));
            pthread_mutex_unlock(mutex);
        }
        
        flb_free(attrs);
        flb_free(pod_name);
    }

cleanup:
    flb_plg_debug(ctx->ins, "ended parsing pod to service map");
    msgpack_unpacked_destroy(&api_result);
    if (buffer) {
        flb_free(buffer);
    }
}

int fetch_pod_service_map(struct flb_kube *ctx, char *api_server_url,
                          pthread_mutex_t *mutex)
{
    if (!ctx->aws_use_pod_association) {
        return -1;
    }
    int ret;
    struct flb_http_client *c;
    size_t b_sent;
    struct flb_connection *u_conn;
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
        if (!ctx->aws_pod_association_upstream) {
            flb_plg_debug(ctx->ins, "[kubernetes] upstream object for pod association"
                                    " is NULL. Making a new one now");
            ret = flb_kube_pod_association_init(ctx,ctx->config);
            if (ret == -1) {
                return -1;
            }
        }

        u_conn = flb_upstream_conn_get(ctx->aws_pod_association_upstream);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "[kubernetes] no upstream connections available to %s:%i",
                          ctx->aws_pod_association_upstream->tcp_host,
                          ctx->aws_pod_association_upstream->tcp_port);
            flb_upstream_destroy(ctx->aws_pod_association_upstream);
            flb_tls_destroy(ctx->aws_pod_association_tls);
            ctx->aws_pod_association_upstream = NULL;
            ctx->aws_pod_association_tls = NULL;
            return -1;
        }

        /* Create HTTP client */
        c = flb_http_client(u_conn, FLB_HTTP_GET,
                            api_server_url,
                            NULL, 0, ctx->aws_pod_association_host,
                            ctx->aws_pod_association_port, NULL, 0);

        if (!c) {
            flb_error("[kubernetes] could not create HTTP client");
            flb_upstream_conn_release(u_conn);
            flb_upstream_destroy(ctx->aws_pod_association_upstream);
            flb_tls_destroy(ctx->aws_pod_association_tls);
            ctx->aws_pod_association_upstream = NULL;
            ctx->aws_pod_association_tls = NULL;
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

/* Determine platform by checking aws-auth configmap */
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
            flb_plg_debug(ctx->ins, "Cluster name is %s.", meta->cluster);
        }
    }
}
