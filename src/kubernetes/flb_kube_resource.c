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

#include <fluent-bit/flb_kubernetes.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>

#include <msgpack.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

static int msgpack_str_eq(msgpack_object obj, const char *str, size_t len)
{
    if (obj.type != MSGPACK_OBJECT_STR || obj.via.str.size != len) {
        return FLB_FALSE;
    }

    if (strncmp(obj.via.str.ptr, str, len) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int msgpack_map_get(msgpack_object map, const char *key,
                           msgpack_object *out)
{
    int i;
    size_t key_len;

    if (map.type != MSGPACK_OBJECT_MAP || key == NULL || out == NULL) {
        return -1;
    }

    key_len = strlen(key);
    for (i = 0; i < map.via.map.size; i++) {
        if (msgpack_str_eq(map.via.map.ptr[i].key, key, key_len)) {
            *out = map.via.map.ptr[i].val;
            return 0;
        }
    }

    return -1;
}

static flb_sds_t msgpack_map_get_sds(msgpack_object map, const char *key)
{
    int ret;
    msgpack_object val;

    ret = msgpack_map_get(map, key, &val);
    if (ret != 0 || val.type != MSGPACK_OBJECT_STR) {
        return NULL;
    }

    return flb_sds_create_len(val.via.str.ptr, val.via.str.size);
}

int flb_kube_resource_get_pod(struct flb_kube_client *client,
                              const char *namespace, const char *podname,
                              char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;
    char uri[1024];

    ret = snprintf(uri, sizeof(uri),
                   FLB_KUBE_API_POD_FMT, namespace, podname);
    if (ret < 0 || (size_t) ret >= sizeof(uri)) {
        return -1;
    }

    ret = flb_kube_client_get(client, FLB_KUBE_CLIENT_API, uri,
                              out_buf, out_size, &root_type);
    return ret == -1 ? -1 : 0;
}

int flb_kube_resource_get_namespace(struct flb_kube_client *client,
                                    const char *namespace,
                                    char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;
    char uri[1024];

    ret = snprintf(uri, sizeof(uri),
                   FLB_KUBE_API_NAMESPACE_FMT, namespace);
    if (ret < 0 || (size_t) ret >= sizeof(uri)) {
        return -1;
    }

    ret = flb_kube_client_get(client, FLB_KUBE_CLIENT_API, uri,
                              out_buf, out_size, &root_type);
    return ret == -1 ? -1 : 0;
}

int flb_kube_resource_get_configmap(struct flb_kube_client *client,
                                    const char *namespace,
                                    const char *configmap,
                                    char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;
    char uri[1024];

    ret = snprintf(uri, sizeof(uri),
                   FLB_KUBE_API_CONFIGMAP_FMT, namespace, configmap);
    if (ret < 0 || (size_t) ret >= sizeof(uri)) {
        return -1;
    }

    ret = flb_kube_client_get(client, FLB_KUBE_CLIENT_API, uri,
                              out_buf, out_size, &root_type);
    return ret == -1 ? -1 : 0;
}

int flb_kube_resource_get_kubelet_pods(struct flb_kube_client *client,
                                       char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;

    ret = flb_kube_client_get(client, FLB_KUBE_CLIENT_KUBELET,
                              FLB_KUBELET_PODS,
                              out_buf, out_size, &root_type);
    return ret == -1 ? -1 : 0;
}

int flb_kube_resource_get_pods_by_node(struct flb_kube_client *client,
                                       const char *node_name,
                                       struct mk_list *results)
{
    int ret;
    int i;
    int count = 0;
    char *buf = NULL;
    size_t size = 0;
    msgpack_object root;
    msgpack_object items;
    msgpack_unpacked result;
    char uri[1024];

    if (client == NULL || node_name == NULL || results == NULL) {
        return -1;
    }

    ret = snprintf(uri, sizeof(uri),
                   "/api/v1/pods?fieldSelector=spec.nodeName=%s", node_name);
    if (ret < 0 || (size_t) ret >= sizeof(uri)) {
        return -1;
    }

    ret = flb_kube_client_get(client, FLB_KUBE_CLIENT_API, uri,
                              &buf, &size, NULL);
    if (ret == -1) {
        return -1;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, NULL);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
        return -1;
    }

    root = result.data;
    ret = msgpack_map_get(root, "items", &items);
    if (ret != 0 || items.type != MSGPACK_OBJECT_ARRAY) {
        msgpack_unpacked_destroy(&result);
        flb_free(buf);
        return -1;
    }

    for (i = 0; i < items.via.array.size; i++) {
        int j;
        msgpack_object pod;
        msgpack_object status;
        msgpack_object metadata;
        msgpack_object annotations;
        flb_sds_t pod_ip = NULL;
        flb_sds_t scrape = NULL;
        flb_sds_t port = NULL;
        flb_sds_t path = NULL;
        flb_sds_t entry = NULL;
        flb_sds_t tmp = NULL;

        pod = items.via.array.ptr[i];
        if (pod.type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        if (msgpack_map_get(pod, "status", &status) == 0) {
            pod_ip = msgpack_map_get_sds(status, "podIP");
        }

        if (msgpack_map_get(pod, "metadata", &metadata) == 0 &&
            msgpack_map_get(metadata, "annotations", &annotations) == 0 &&
            annotations.type == MSGPACK_OBJECT_MAP) {
            for (j = 0; j < annotations.via.map.size; j++) {
                msgpack_object key;
                msgpack_object val;

                key = annotations.via.map.ptr[j].key;
                val = annotations.via.map.ptr[j].val;
                if (val.type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                if (msgpack_str_eq(key, "prometheus.io/scrape", 20)) {
                    flb_sds_destroy(scrape);
                    scrape = flb_sds_create_len(val.via.str.ptr,
                                                val.via.str.size);
                }
                else if (msgpack_str_eq(key, "prometheus.io/port", 18)) {
                    flb_sds_destroy(port);
                    port = flb_sds_create_len(val.via.str.ptr,
                                              val.via.str.size);
                }
                else if (msgpack_str_eq(key, "prometheus.io/path", 18)) {
                    flb_sds_destroy(path);
                    path = flb_sds_create_len(val.via.str.ptr,
                                              val.via.str.size);
                }
            }
        }

        if (pod_ip != NULL && scrape != NULL && flb_sds_len(scrape) == 4 &&
            strncasecmp(scrape, "true", 4) == 0) {
            if (port == NULL) {
                port = flb_sds_create("80");
            }
            if (path == NULL) {
                path = flb_sds_create("/metrics");
            }
            if (port == NULL || path == NULL) {
                goto pod_cleanup;
            }

            entry = flb_sds_create_size(flb_sds_len(pod_ip) +
                                        flb_sds_len(port) +
                                        flb_sds_len(path) + 3);
            if (entry != NULL) {
                tmp = flb_sds_printf(&entry, "%s:%s%s", pod_ip, port, path);
                if (tmp != NULL) {
                    if (flb_slist_add_sds(results, entry) == 0) {
                        count++;
                        entry = NULL;
                    }
                }
                flb_sds_destroy(entry);
            }
        }

pod_cleanup:
        flb_sds_destroy(pod_ip);
        flb_sds_destroy(scrape);
        flb_sds_destroy(port);
        flb_sds_destroy(path);
    }

    msgpack_unpacked_destroy(&result);
    flb_free(buf);

    return count;
}
