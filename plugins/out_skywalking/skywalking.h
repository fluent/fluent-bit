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

#ifndef FLB_OUT_SKYWALKING_H
#define FLB_OUT_SKYWALKING_H

#include <fluent-bit/flb_output_plugin.h>

struct flb_output_sw {
  /* Configured by user */
  flb_sds_t auth_token;
  flb_sds_t svc_name;
  flb_sds_t svc_inst_name;

  /* Upstream log collector context */
  struct flb_upstream *u;

  /* Output plugin instance */
  struct flb_output_instance *ins;

  flb_sds_t http_scheme;
  flb_sds_t uri;
};

#endif
