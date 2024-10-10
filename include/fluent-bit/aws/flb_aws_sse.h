/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_AWS_SSE
#define FLB_AWS_SSE

// Per https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html#API_PutObject_ResponseSyntax
#include <sys/types.h>
#define FLB_AWS_SSE_NONE  0
#define FLB_AWS_SSE_AWSKMS  1
#define FLB_AWS_SSE_AES256 2

/*
 * Get sse type from sse keyword. The return value is used to identify
 * what sse option to utilize.
 *
 * Returns int sse type id - FLB_AWS_SSE_<sse-type>
 */
int flb_aws_sse_get_type(const char *sse_keyword);

#endif
