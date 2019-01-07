/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_FILTER_KUBE_PROP_H
#define FLB_FILTER_KUBE_PROP_H

#include "kube_meta.h"
#include "kube_props.h"

int flb_kube_prop_set(struct flb_kube *ctx, struct flb_kube_meta *meta,
                      char *prop, int prop_len,
                      char *val_buf, size_t val_len,
                      struct flb_kube_props *props);
int flb_kube_prop_pack(struct flb_kube_props *props,
                       void **out_buf, size_t *out_size);
int flb_kube_prop_unpack(struct flb_kube_props *props, char *buf, size_t size);
void flb_kube_prop_destroy(struct flb_kube_props *props);

#endif
