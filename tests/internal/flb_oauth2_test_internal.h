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

#ifndef FLB_OAUTH2_TEST_INTERNAL_H
#define FLB_OAUTH2_TEST_INTERNAL_H

#include <fluent-bit/flb_oauth2.h>

int oauth2_token_source_parse(const char *value, int *out);

int oauth2_metadata_split_header(const char *header,
                                 flb_sds_t *name_out,
                                 flb_sds_t *value_out);

flb_sds_t oauth2_metadata_build_url(struct flb_oauth2 *ctx);

int oauth2_metadata_refresh_locked(struct flb_oauth2 *ctx);

int oauth2_dispatch_refresh_locked(struct flb_oauth2 *ctx);

#endif
