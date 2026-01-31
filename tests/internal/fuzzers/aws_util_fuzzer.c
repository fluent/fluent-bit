/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023 The Fluent Bit Authors
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

#include <stdint.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include "flb_fuzz_header.h"

int initialization_crutch()
{
    struct flb_config *config;
    config = flb_config_init();
    if (config == NULL) {
        return -1;
    }
    flb_config_exit(config);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *format = NULL;
    char *tag = NULL;
    char *tag_delimiter = NULL;

    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 4) {
        return 0;
    }
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    if (size < 300) {
        return 0;
    }

    format = get_null_terminated(50, &data, &size);
    tag = get_null_terminated(100, &data, &size);
    tag_delimiter = get_null_terminated(100, &data, &size);

    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;
    memset(&t, 0, sizeof(time_t));

    if (format && tag && tag_delimiter) {
        if (!initialization_crutch()) {
            flb_sds_t s3_key_format = NULL;
            s3_key_format = flb_get_s3_key(format, t, tag, tag_delimiter, 0, NULL);
            if (s3_key_format) {
                flb_sds_destroy(s3_key_format);
            }
            if (size > 200) {
                char *json_val = get_null_terminated(100, &data, &size);
                if (json_val != NULL) {
                    flb_sds_t s1 = flb_aws_error(json_val, strlen(json_val));
                    if (s1 != NULL) {
                        flb_sds_destroy(s1);
                    }
                    flb_free(json_val);
                }
                char *xml_val = get_null_terminated(100, &data, &size);
                if (xml_val != NULL) {
                    flb_sds_t s2 = flb_aws_xml_error(xml_val, strlen(xml_val));
                    if (s2 != NULL) {
                        flb_sds_destroy(s2);
                    }
                    flb_free(xml_val);
                }
            }
        }
    }
    if (format) {
        flb_free(format);
    }
    if (tag) {
        flb_free(tag);
    }
    if (tag_delimiter) {
        flb_free(tag_delimiter);
    }
    return 0;
}
