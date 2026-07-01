/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022-2026 The Fluent Bit Authors
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

#ifndef FLB_WE_OS_H
#define FLB_WE_OS_H

#include "we.h"

#define WE_OS_CURRENT_VERSION_PATH  \
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

int we_os_init(struct flb_we *ctx);
int we_os_exit(struct flb_we *ctx);
int we_os_update(struct flb_we *ctx);

#endif
