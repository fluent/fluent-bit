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

#ifndef FLB_FILTER_LOOKUP_H
#define FLB_FILTER_LOOKUP_H

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_hash_table.h>

struct lookup_ctx {
    struct flb_filter_instance *ins;
    char *file;
    char *lookup_key;
    char *result_key;
    struct flb_hash_table *ht;
    int ignore_case;
};

extern struct flb_filter_plugin filter_lookup_plugin;

#endif /* FLB_FILTER_LOOKUP_H */