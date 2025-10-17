/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_IN_SYSLOG_PROT_H
#define FLB_IN_SYSLOG_PROT_H

#include <fluent-bit/flb_info.h>

#include <stdint.h>

#include "syslog.h"

#define FLB_MAP_EXPAND_SUCCESS   0
#define FLB_MAP_NOT_MODIFIED    -1
#define FLB_MAP_EXPANSION_ERROR -2
#define FLB_MAP_EXPANSION_INVALID_VALUE_TYPE -3

int syslog_prot_process(struct syslog_conn *conn);
int syslog_prot_process_udp(struct syslog_conn *conn);

#endif
