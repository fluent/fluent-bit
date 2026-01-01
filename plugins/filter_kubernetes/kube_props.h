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

#ifndef FLB_FILTER_KUBE_PROPS_H
#define FLB_FILTER_KUBE_PROPS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

/* Property structure/array index */
#define FLB_KUBE_PROPS_STDOUT_PARSER   0
#define FLB_KUBE_PROPS_STDERR_PARSER   1
#define FLB_KUBE_PROPS_STDOUT_EXCLUDE  2
#define FLB_KUBE_PROPS_STDERR_EXCLUDE  3
#define FLB_KUBE_NUMBER_OF_PROPS       4

#define FLB_KUBE_PROP_UNDEF 0
#define FLB_KUBE_PROP_FALSE 1
#define FLB_KUBE_PROP_TRUE 2

struct flb_kube_props {
    flb_sds_t stdout_parser; /* suggested parser for stdout */
    flb_sds_t stderr_parser; /* suggested parser for stderr */
    int stdout_exclude;      /* bool: exclude stdout logs ? */
    int stderr_exclude;      /* bool: exclude stderr logs ? */
};

#endif
