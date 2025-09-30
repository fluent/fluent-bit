/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  ========
 *  Copyright 2024 The CProfiles Authors
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

#ifndef CPROF_MPACK_UTILS_DEFS_H
#define CPROF_MPACK_UTILS_DEFS_H

#define CPROF_MPACK_SUCCESS                    0
#define CPROF_MPACK_INSUFFICIENT_DATA          1
#define CPROF_MPACK_INVALID_ARGUMENT_ERROR     2
#define CPROF_MPACK_ALLOCATION_ERROR           3
#define CPROF_MPACK_CORRUPT_INPUT_DATA_ERROR   4
#define CPROF_MPACK_CONSUME_ERROR              5
#define CPROF_MPACK_ENGINE_ERROR               6
#define CPROF_MPACK_PENDING_MAP_ENTRIES        7
#define CPROF_MPACK_PENDING_ARRAY_ENTRIES      8
#define CPROF_MPACK_UNEXPECTED_KEY_ERROR       9
#define CPROF_MPACK_UNEXPECTED_DATA_TYPE_ERROR 10
#define CPROF_MPACK_ERROR_CUTOFF               20

#define CPROF_MPACK_MAX_ARRAY_ENTRY_COUNT      65535
#define CPROF_MPACK_MAX_MAP_ENTRY_COUNT        1024
#define CPROF_MPACK_MAX_STRING_LENGTH          1024

#endif