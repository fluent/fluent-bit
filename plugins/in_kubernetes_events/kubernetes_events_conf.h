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

#ifndef FLB_IN_KUBERNETES_EVENTS_CONF_H
#define FLB_IN_KUBERNETES_EVENTS_CONF_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "kubernetes_events.h"

/* Kubernetes API server info */
#define K8S_EVENTS_KUBE_API_HOST "kubernetes.default.svc"
#define K8S_EVENTS_KUBE_API_PORT 443
// /apis/events.k8s.io/v1/events
// /apis/events.k8s.io/v1/namespaces/{namespace}/events
#define K8S_EVENTS_KUBE_API_URI  "/api/v1/events"
#define K8S_EVENTS_KUBE_NAMESPACE_API_URI  "/api/v1/namespaces/%s/events"

/* secrets */
#define K8S_EVENTS_KUBE_TOKEN          "/var/run/secrets/kubernetes.io/serviceaccount/token"
#define K8S_EVENTS_KUBE_CA             "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

#define K8S_EVENTS_RA_RESOURCE_VERSION "$metadata['resourceVersion']"

struct k8s_events *k8s_events_conf_create(struct flb_input_instance *ins);
void k8s_events_conf_destroy(struct k8s_events *ctx);

#endif