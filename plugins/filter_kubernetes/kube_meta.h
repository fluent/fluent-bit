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

#ifndef FLB_FILTER_KUBE_META_H
#define FLB_FILTER_KUBE_META_H

#include "kube_props.h"

struct flb_kube;

struct flb_kube_meta {
    int fields;

    int cluster_len;
    int namespace_len;
    int podname_len;
    int cache_key_len;
    int container_name_len;
    int docker_id_len;
    int container_hash_len;
    int container_image_len;
    int workload_len;

    char *cluster;
    char *namespace;
    char *podname;
    char *container_name;
    char *container_image;
    char *docker_id;
    char *workload;

    char *container_hash;   /* set only on Systemd mode */

    char *cache_key;
};

/* Constant Kubernetes paths */
#define FLB_KUBE_NAMESPACE "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
#define FLB_KUBE_TOKEN "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define FLB_KUBE_CA "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
#define FLB_KUBE_API_HOST "kubernetes.default.svc"
#define FLB_KUBE_API_PORT 443
#define FLB_KUBE_API_POD_FMT "/api/v1/namespaces/%s/pods/%s"
#define FLB_KUBE_API_NAMESPACE_FMT "/api/v1/namespaces/%s"
#define FLB_KUBE_API_CONFIGMAP_FMT "/api/v1/namespaces/%s/configmaps/%s"
#define FLB_KUBELET_PODS "/pods"

/* Constants for possible kubernetes resources */
#define FLB_KUBE_POD "pod"
#define FLB_KUBE_CONFIGMAP "configmap"

int flb_kube_meta_init(struct flb_kube *ctx, struct flb_config *config);
int flb_kube_meta_fetch(struct flb_kube *ctx);
int flb_kube_dummy_meta_get(char **out_buf, size_t *out_size);
int flb_kube_meta_get(struct flb_kube *ctx,
                      const char *tag, int tag_len,
                      const char *data, size_t data_size,
                      const char **out_buf, size_t *out_size,
                      const char **namespace_out_buf,
                      size_t *namespace_out_size,
                      struct flb_kube_meta *meta,
                      struct flb_kube_props *props,
                      struct flb_kube_meta *namespace_meta);
int flb_kube_meta_release(struct flb_kube_meta *meta);
int flb_kube_pod_association_init(struct flb_kube *ctx, struct flb_config *config);
int get_api_server_configmap(struct flb_kube *ctx, const char *namespace, const char *configmap, char **out_buf, size_t *out_size);

#endif
