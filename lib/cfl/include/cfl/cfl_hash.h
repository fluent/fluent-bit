/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#ifndef CFL_HASH_H
#define CFL_HASH_H

/* NOTE: this is just a wrapper for naming convention */

#include <stdint.h>
#include "xxh3.h"

#define cfl_hash_64bits_t      XXH64_hash_t
#define cfl_hash_state_t       XXH3_state_t
#define cfl_hash_64bits_reset  XXH3_64bits_reset
#define cfl_hash_64bits_update XXH3_64bits_update
#define cfl_hash_64bits_digest XXH3_64bits_digest
#define cfl_hash_64bits        XXH3_64bits

#define cfl_hash_128bits_t     XXH128_hash_t
#define cfl_hash_128bits       XXH3_128bits

#endif
