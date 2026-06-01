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

#include <fluent-bit/flb_kubernetes.h>

struct flb_hash_table *flb_kube_meta_cache_create(int ttl, int size)
{
    if (size <= 0) {
        return NULL;
    }

    if (ttl > 0) {
        return flb_hash_table_create_with_ttl(ttl,
                                              FLB_HASH_TABLE_EVICT_OLDER,
                                              size,
                                              size);
    }

    return flb_hash_table_create(FLB_HASH_TABLE_EVICT_RANDOM,
                                 size,
                                 size);
}

void flb_kube_meta_cache_destroy(struct flb_hash_table *cache)
{
    if (cache != NULL) {
        flb_hash_table_destroy(cache);
    }
}
