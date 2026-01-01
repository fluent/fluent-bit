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

#ifndef FLB_KERNEL_H
#define FLB_KERNEL_H

#include <inttypes.h>
#include <monkey/mk_core.h>

/* Numeric kernel version */
#define FLB_KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

struct flb_kernel {
    uint8_t minor;
    uint8_t major;
    uint8_t patch;
    uint32_t n_version;
    mk_ptr_t s_version;
};

struct flb_kernel *flb_kernel_info();
void flb_kernel_destroy(struct flb_kernel *kernel);

#endif
