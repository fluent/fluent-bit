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

#ifndef FLB_KUBERNETES_H
#define FLB_KUBERNETES_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_upstream.h>

#include <time.h>

#define FLB_KUBE_NAMESPACE "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
#define FLB_KUBE_TOKEN     "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define FLB_KUBE_CA        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
#define FLB_KUBE_API_HOST  "kubernetes.default.svc"
#define FLB_KUBE_API_PORT  443

#define FLB_KUBE_API_POD_FMT       "/api/v1/namespaces/%s/pods/%s"
#define FLB_KUBE_API_NAMESPACE_FMT "/api/v1/namespaces/%s"
#define FLB_KUBE_API_CONFIGMAP_FMT "/api/v1/namespaces/%s/configmaps/%s"
#define FLB_KUBELET_PODS           "/pods"

#define FLB_KUBE_CLIENT_API     0
#define FLB_KUBE_CLIENT_KUBELET 1

struct flb_kube_client_config {
    const char *api_host;
    int api_port;
    int api_https;

    const char *kubelet_host;
    int kubelet_port;
    int kubelet_https;
    int use_kubelet;

    const char *tls_ca_path;
    const char *tls_ca_file;
    const char *tls_vhost;
    int tls_debug;
    int tls_verify;
    int tls_verify_hostname;

    const char *token_file;
    const char *token_command;
    int token_ttl;

    size_t buffer_size;
};

struct flb_kube_client {
    struct flb_config *config;

    flb_sds_t api_host;
    int api_port;
    int api_https;

    flb_sds_t kubelet_host;
    int kubelet_port;
    int kubelet_https;
    int use_kubelet;

    flb_sds_t tls_ca_path;
    flb_sds_t tls_ca_file;
    flb_sds_t tls_vhost;
    int tls_debug;
    int tls_verify;
    int tls_verify_hostname;

    flb_sds_t token_file;
    flb_sds_t token_command;
    int token_ttl;
    time_t token_create;

    char *token;
    size_t token_len;
    char *auth;
    size_t auth_size;
    size_t auth_len;

    size_t buffer_size;

    struct flb_tls *api_tls;
    struct flb_tls *kubelet_tls;
    struct flb_upstream *api_upstream;
    struct flb_upstream *kubelet_upstream;
};

struct flb_kube_client *flb_kube_client_create(
                                    struct flb_config *config,
                                    struct flb_kube_client_config *client_config);
void flb_kube_client_destroy(struct flb_kube_client *client);

int flb_kube_client_refresh_token(struct flb_kube_client *client);
int flb_kube_client_load_local_pod_info(struct flb_kube_client *client,
                                        char **namespace, size_t *namespace_len,
                                        char **podname, size_t *podname_len);
int flb_kube_client_get(struct flb_kube_client *client,
                        int connection,
                        const char *uri,
                        char **out_buf, size_t *out_size,
                        int *root_type);

int flb_kube_resource_get_pod(struct flb_kube_client *client,
                              const char *namespace, const char *podname,
                              char **out_buf, size_t *out_size);
int flb_kube_resource_get_namespace(struct flb_kube_client *client,
                                    const char *namespace,
                                    char **out_buf, size_t *out_size);
int flb_kube_resource_get_configmap(struct flb_kube_client *client,
                                    const char *namespace,
                                    const char *configmap,
                                    char **out_buf, size_t *out_size);
int flb_kube_resource_get_kubelet_pods(struct flb_kube_client *client,
                                       char **out_buf, size_t *out_size);
int flb_kube_resource_get_pods_by_node(struct flb_kube_client *client,
                                       const char *node_name,
                                       struct mk_list *results);

struct flb_hash_table *flb_kube_meta_cache_create(int ttl, int size);
void flb_kube_meta_cache_destroy(struct flb_hash_table *cache);

#endif
