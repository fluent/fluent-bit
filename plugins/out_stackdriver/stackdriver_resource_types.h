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

#ifndef FLB_OUT_STACKDRIVER_RESOURCE_TYPES_H
#define FLB_OUT_STACKDRIVER_RESOURCE_TYPES_H

#include "stackdriver.h"

#define MAX_RESOURCE_ENTRIES 10
#define MAX_REQUIRED_LABEL_ENTRIES 10

#define RESOURCE_TYPE_K8S 1
#define RESOURCE_TYPE_GENERIC_NODE 2
#define RESOURCE_TYPE_GENERIC_TASK 3

struct resource_type {
    int id;
    char* resources[MAX_RESOURCE_ENTRIES];
    char* required_labels[MAX_REQUIRED_LABEL_ENTRIES];
};

void set_resource_type(struct flb_stackdriver *ctx);
int resource_api_has_required_labels(struct flb_stackdriver *ctx);

#endif
