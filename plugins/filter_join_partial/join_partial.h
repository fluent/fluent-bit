/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2018 SpareBank 1 Banksamarbeidet DA
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

#ifndef FLB_FILTER_JOIN_PARTIAL_H
#define FLB_FILTER_JOIN_PARTIAL_H

#define FLB_HASH_TABLE_SIZE 256

#define FORMAT_DOCKER 1
#define FORMAT_CRI_O 2

struct filter_join_partial_ctx
{
    char* log_key;
    int log_key_len;

    struct flb_hash *hash_table;
};

#endif