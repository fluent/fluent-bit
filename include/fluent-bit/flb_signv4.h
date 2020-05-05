/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>

#ifdef FLB_HAVE_SIGNV4

#ifndef FLB_SIGNV4_H
#define FLB_SIGNV4_H


flb_sds_t flb_signv4_uri_normalize_path(char *uri, size_t len);

flb_sds_t flb_signv4_do(struct flb_http_client *c, int normalize_uri,
                        int amz_date,
                        time_t t_now,
                        char *access_key,
                        char *region, char *service,
                        char *secret_key, char *security_token);

#endif
#endif /* FLB_HAVE_SIGNV4 */
