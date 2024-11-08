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


#include <fluent-bit/flb_unicode.h>
#include <stddef.h>

int flb_unicode_convert(int preferred_encoding, const char *input, size_t length,
                        char **output, size_t *out_size)
{
#ifdef FLB_HAVE_UNICODE_ENCODER
    return flb_simdutf_connector_convert_from_unicode(preferred_encoding, input, length,
                                                      output, out_size);
#else
    return FLB_UNICODE_CONVERT_UNSUPPORTED;
#endif
}

int flb_unicode_validate(const char *record, size_t size)
{
#ifdef FLB_HAVE_UNICODE_ENCODER
    return flb_simdutf_connector_validate_utf8(record, size);
#else
    return -1;
#endif
}
