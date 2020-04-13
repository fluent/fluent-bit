/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_HS_API_V1_METRICS_H
#define FLB_HS_API_V1_METRICS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_sds.h>

int api_v1_metrics(struct flb_hs *hs);

flb_sds_t metrics_help_txt(char *metric_name, flb_sds_t *metric_helptxt);

#endif
