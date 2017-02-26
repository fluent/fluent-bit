/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

struct flb_kube;

struct flb_kube_meta {
    char *namespace;
    size_t namespace_len;

    char *token;
    size_t token_len;

    char *hostname;
    size_t hostname_len;

    char *auth;
    size_t auth_len;

    char api_endpoint[1024];

    time_t updated;
    msgpack_packer *mp_pck;
};

/* Constant Kubernetes paths */
#define FLB_KUBE_NAMESPACE "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
#define FLB_KUBE_TOKEN "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define FLB_KUBE_CA "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
#define FLB_KUBE_API_HOST "kubernetes.default.svc"
#define FLB_KUBE_API_PORT 443
#define FLB_KUBE_API_FMT "https://kubernetes.default.svc/api/v1/namespaces/%s/pods/%s"

int flb_kube_meta_init(struct flb_kube *ctx, struct flb_config *config);
int flb_kube_meta_fetch(struct flb_kube *ctx);
int flb_kube_meta_get(struct flb_kube *ctx,
                      char *tag, int tag_len,
                      char **out_buf, size_t *out_size);
#endif
