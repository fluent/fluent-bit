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

#include <fluent-bit/flb_log.h>

#include <fluent-bit/aws/flb_aws_sse.h>

#include <stdint.h>

struct sse_option {
    int sse_type;
    char *sse_keyword;
};

/*
 * Library of sse options
 * AWS plugins that support sse will have these options.
 * Referenced function should return -1 on error and 0 on success.
 */
static const struct sse_option sse_options[] = {
    /* FLB_AWS_SSE_NONE which is 0 is reserved for array footer */
    {
        FLB_AWS_SSE_AWSKMS,
        "aws:kms"
    },
    {
        FLB_AWS_SSE_AES256,
        "AES256"
    },
    { 0 }
};

int flb_aws_sse_get_type(const char *sse_keyword)
{
    int ret;
    const struct sse_option *o;

    o = sse_options;

    while (o->sse_type != 0) {
        ret = strcmp(o->sse_keyword, sse_keyword);
        if (ret == 0) {
            return o->sse_type;
        }
        ++o;
    }

    flb_error("[aws] unknown sse type: %s", sse_keyword);
    return -1;
}
