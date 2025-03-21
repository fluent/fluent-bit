/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_FILTER_NIGHTFALL_API_H
#define FLB_FILTER_NIGHTFALL_API_H

#define FLB_FILTER_NIGHTFALL_API_URL  "https://api.nightfall.ai/"
#define FLB_FILTER_NIGHTFALL_API_HOST "api.nightfall.ai"

#include "nightfall.h"

int scan_log(struct flb_filter_nightfall *ctx, msgpack_object *data, 
             char **to_redact, size_t *to_redact_size, char *is_sensitive);

#endif
