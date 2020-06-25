/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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


#ifndef FLB_STD_OPERATION_H
#define FLB_STD_OPERATION_H

#include "stackdriver.h"

void add_operation_field(flb_sds_t *operation_id, flb_sds_t *operation_producer, 
                         int *operation_first, int *operation_last, 
                         msgpack_packer *mp_pck);

int extract_operation(flb_sds_t *operation_id, flb_sds_t *operation_producer, 
                      int *operation_first, int *operation_last, 
                      msgpack_object *obj, int *extra_subfields);

void pack_extra_operation_subfields(msgpack_packer *mp_pck, msgpack_object *operation, int extra_subfields);


#endif
