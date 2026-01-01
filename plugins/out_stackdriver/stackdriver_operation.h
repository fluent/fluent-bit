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


#ifndef FLB_STD_OPERATION_H
#define FLB_STD_OPERATION_H

#include "stackdriver.h"

/* subfield name and size */
#define OPERATION_ID "id"
#define OPERATION_PRODUCER "producer"
#define OPERATION_FIRST "first"
#define OPERATION_LAST "last"

#define OPERATION_ID_SIZE 2
#define OPERATION_PRODUCER_SIZE 8
#define OPERATION_FIRST_SIZE 5
#define OPERATION_LAST_SIZE 4

/* 
 *  Add operation field to the entries.
 *  The structure of operation is:
 *  {
 *      "id": string,
 *      "producer": string,
 *      "first": boolean,
 *      "last": boolean
 *  }
 * 
 */                                                                                     
void add_operation_field(flb_sds_t *operation_id, flb_sds_t *operation_producer, 
                         int *operation_first, int *operation_last, 
                         msgpack_packer *mp_pck);

/*
 *  Extract the operation field from the jsonPayload.
 *  If the operation field exists, return TRUE and store the subfields.
 *  If there are extra subfields, count the number.
 */
int extract_operation(flb_sds_t *operation_id, flb_sds_t *operation_producer, 
                      int *operation_first, int *operation_last, 
                      msgpack_object *obj, int *extra_subfields);

/*
 *  When there are extra subfields, we will preserve the extra subfields inside jsonPayload
 *  For example, if the jsonPayload is as followed：
 *  jsonPayload {
 *      "logging.googleapis.com/operation": {
 *          "id": "id1",
 *          "producer": "id2",
 *          "first": true,
 *          "last": true,
 *          "extra": "some string"  #extra subfield
 *      }
 *  }
 *  We will preserve the extra subfields. The jsonPayload after extracting is:
 *  jsonPayload {
 *      "logging.googleapis.com/operation": {
 *          "extra": "some string" 
 *      }
 *  }
 */
void pack_extra_operation_subfields(msgpack_packer *mp_pck, msgpack_object *operation, 
                                    int extra_subfields);


#endif
