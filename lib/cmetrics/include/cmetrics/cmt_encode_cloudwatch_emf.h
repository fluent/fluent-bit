/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2024 The CMetrics Authors
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


#ifndef CMT_ENCODE_CLOUDWATCH_EMF_H
#define CMT_ENCODE_CLOUDWATCH_EMF_H

#include <time.h>
#include <cfl/cfl.h>
#include <cmetrics/cmetrics.h>

#define CMT_ENCODE_CLOUDWATCH_EMF_SUCCESS                 0
#define CMT_ENCODE_CLOUDWATCH_EMF_INVALID_ARGUMENT_ERROR -1
#define CMT_ENCODE_CLOUDWATCH_EMF_CREATION_FAILED        -2
#define CMT_ENCODE_CLOUDWATCH_EMF_INVALID_DATA_ERROR     -4

/* Metric Unit */
#define CMT_EMF_UNIT_PERCENT "Percent"
#define CMT_EMF_UNIT_BYTES   "Bytes"
#define CMT_EMF_UNIT_COUNTER "Counter"

int cmt_encode_cloudwatch_emf_create(struct cmt *cmt,
                                     char **out_buf, size_t *out_size,
                                     int wrap_array);
void cmt_encode_cloudwatch_emf_destroy(char *out_buf);

#endif
