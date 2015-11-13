/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_ERROR_H
#define FLB_ERROR_H

#define FLB_ERR_CFG_FILE             010
#define FLB_ERR_CFG_FILE_FORMAT      011
#define FLB_ERR_CFG_FLUSH            020
#define FLB_ERR_CFG_FLUSH_CREATE     021
#define FLB_ERR_CFG_FLUSH_REGISTER   022
#define FLB_ERR_INPUT_INVALID        050
#define FLB_ERR_INPUT_UNDEF          051
#define FLB_ERR_INPUT_UNSUP          052
#define FLB_ERR_OUTPUT_UNDEF         100
#define FLB_ERR_OUTPUT_INVALID       101
#define FLB_ERR_OUTPUT_UNIQ          102

/* JSON errors */
#define FLB_ERR_JSON_INVAL           -501
#define FLB_ERR_JSON_PART            -502

#endif
