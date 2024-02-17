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

#ifndef FLB_PROCESSOR_ATTRIBUTES_TRACES_H
#define FLB_PROCESSOR_ATTRIBUTES_TRACES_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_processor.h>

#include <cfl/cfl.h>

int traces_delete_attributes(struct ctrace *traces_context, struct mk_list *attributes);
int traces_update_attributes(struct ctrace *traces_context, struct cfl_list *attributes);
int traces_upsert_attributes(struct ctrace *traces_context, struct cfl_list *attributes);
int traces_convert_attributes(struct ctrace *traces_context, struct cfl_list *attributes);
int traces_extract_attributes(struct ctrace *traces_context, struct cfl_list *attributes);
int traces_insert_attributes(struct ctrace *traces_context, struct cfl_list *attributes);
int traces_hash_attributes(struct ctrace *traces_context, struct mk_list *attributes);



#endif