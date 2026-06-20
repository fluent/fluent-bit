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

#ifndef FLB_ML_GROUP_H
#define FLB_ML_GROUP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

struct flb_ml_group *flb_ml_group_create(struct flb_ml *ml);
void flb_ml_group_destroy(struct flb_ml_group *group);
int flb_ml_group_add_parser(struct flb_ml *ctx, struct flb_ml_parser_ins *p);

/*
 * Append data to a multiline stream group respecting the configured
 * buffer limit. The length of the appended data might be reduced if
 * the limit is reached.
 */
int flb_ml_group_cat(struct flb_ml_stream_group *group,
                     const char *data, size_t len);

#endif
