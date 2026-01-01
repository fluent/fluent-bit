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


#ifndef FLB_STD_SOURCELOCATION_H
#define FLB_STD_SOURCELOCATION_H

#include "stackdriver.h"

/* subfield name and size */
#define SOURCE_LOCATION_FILE "file"
#define SOURCE_LOCATION_LINE "line"
#define SOURCE_LOCATION_FUNCTION "function"

#define SOURCE_LOCATION_FILE_SIZE 4
#define SOURCE_LOCATION_LINE_SIZE 4
#define SOURCE_LOCATION_FUNCTION_SIZE 8

/* 
 *  Add sourceLocation field to the entries.
 *  The structure of sourceLocation is:
 *  {
 *      "file": string,
 *      "line": int,
 *      "function": string
 *  }
 */   
void add_source_location_field(flb_sds_t *source_location_file, 
                               int64_t source_location_line,
                               flb_sds_t *source_location_function, 
                               msgpack_packer *mp_pck);

/*
 *  Extract the sourceLocation field from the jsonPayload.
 *  If the sourceLocation field exists, return TRUE and store the subfields.
 *  If there are extra subfields, count the number.
 */
int extract_source_location(flb_sds_t *source_location_file, 
                            int64_t *source_location_line,
                            flb_sds_t *source_location_function, 
                            msgpack_object *obj, int *extra_subfields);

/*
 *  When there are extra subfields, we will preserve the extra subfields inside jsonPayload
 *  For example, if the jsonPayload is as followed：
 *  jsonPayload {
 *      "logging.googleapis.com/sourceLocation": {
 *          "file": "file1",
 *          "line": 1,
 *          "function": "func1",
 *          "extra": "some string"  #extra subfield
 *      }
 *  }
 *  We will preserve the extra subfields. The jsonPayload after extracting is:
 *  jsonPayload {
 *      "logging.googleapis.com/sourceLocation": {
 *          "extra": "some string" 
 *      }
 *  }
 */
void pack_extra_source_location_subfields(msgpack_packer *mp_pck, 
                                          msgpack_object *source_location, 
                                          int extra_subfields);


#endif
