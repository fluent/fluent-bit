/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_OUTPUT_H
#define FLB_OUTPUT_H

#include <fluent-bit/flb_config.h>

#define FLB_OUTPUT_FLUENT      0
#define FLB_OUTPUT_HTTP        1
#define FLB_OUTPUT_HTTPS       2
#define FLB_OUTPUT_TD_HTTP     3
#define FLB_OUTPUT_TD_HTTPS    4

#define FLB_OUTPUT_FLUENT_Z    (sizeof("fluentd")  - 1) + 3
#define FLB_OUTPUT_HTTP_Z      (sizeof("http")     - 1) + 3
#define FLB_OUTPUT_HTTPS_Z     (sizeof("https")    - 1) + 3
#define FLB_OUTPUT_TD_HTTP_Z   (sizeof("td+http")  - 1) + 3
#define FLB_OUTPUT_TD_HTTPS_Z  (sizeof("td+https") - 1) + 3

/* Default TCP port for Fluentd */
#define FLB_OUTPUT_FLUENT_PORT  "12224"

int flb_output_check(struct flb_config *config, char *output);

#endif
