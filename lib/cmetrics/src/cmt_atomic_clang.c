/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <cmetrics/cmt_atomic.h>

inline int cmt_atomic_initialize()
{
    return 0;
}

inline int cmt_atomic_compare_exchange(uint64_t *storage,
                                       uint64_t old_value, uint64_t new_value)
{
    return __atomic_compare_exchange(storage, &old_value, &new_value, 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); 
}

inline void cmt_atomic_store(uint64_t *storage, uint64_t new_value)
{
    __atomic_store_n(storage, new_value, __ATOMIC_SEQ_CST);
}

inline uint64_t cmt_atomic_load(uint64_t *storage)
{
    return __atomic_load_n(storage, __ATOMIC_SEQ_CST);
}
