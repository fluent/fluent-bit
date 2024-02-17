/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <cfl/cfl.h>

#include "variant_utils.h"

#include <stdio.h>
#include <math.h>

cfl_sds_t cfl_variant_convert_to_json(struct cfl_variant *value)
{
    cfl_sds_t      json_result;
    mpack_writer_t writer;
    char          *data;
    size_t         size;

    data = NULL;
    size = 0;

    mpack_writer_init_growable(&writer, &data, &size);

    pack_cfl_variant(&writer, value);

    mpack_writer_destroy(&writer);

    json_result = flb_msgpack_raw_to_json_sds(data, size);

    return json_result;
}


int cfl_variant_convert(struct cfl_variant *input_value,
                        struct cfl_variant **output_value,
                        int output_type)
{
    char              *converstion_canary;
    struct cfl_variant temporary_value;
    int                errno_backup;

    errno_backup = errno;
    *output_value = cfl_variant_create();

    memset(&temporary_value, 0, sizeof(struct cfl_variant));

    temporary_value.type = output_type;

    if (input_value->type == CFL_VARIANT_STRING ||
        input_value->type == CFL_VARIANT_BYTES ||
        input_value->type == CFL_VARIANT_REFERENCE) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string =
                cfl_sds_create_len(
                    input_value->data.as_string,
                    cfl_sds_len(input_value->data.as_string));

            if (temporary_value.data.as_string == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            temporary_value.data.as_bool = CFL_FALSE;

            if (strcasecmp(input_value->data.as_string, "true") == 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
            else if (strcasecmp(input_value->data.as_string, "off") == 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
        }
        else if (output_type == CFL_VARIANT_INT) {
            errno = 0;
            temporary_value.data.as_int64 = strtoimax(input_value->data.as_string,
                                                      &converstion_canary,
                                                      10);

            if (errno == ERANGE || errno == EINVAL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                errno = errno_backup;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            errno = 0;
            converstion_canary = NULL;
            temporary_value.data.as_double = strtod(input_value->data.as_string,
                                                    &converstion_canary);

            if (errno == ERANGE) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                errno = errno_backup;

                return CFL_FALSE;
            }
            else if (temporary_value.data.as_double == 0 &&
                     converstion_canary == input_value->data.as_string) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                errno = errno_backup;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_ARRAY) {
            temporary_value.data.as_array = cfl_array_create(1);

            if (temporary_value.data.as_array == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            if (cfl_array_append_bytes(temporary_value.data.as_array,
                                       input_value->data.as_bytes,
                                       cfl_sds_len(input_value->data.as_bytes)) != 0) {
                cfl_array_destroy(temporary_value.data.as_array);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            temporary_value.data.as_array->entries[0]->type = output_type;
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_INT) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_sds_create_size(64);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }

            /* We need to fix the wesleys truncation PR to cfl */
            converstion_canary = (char *) cfl_sds_printf(
                                            &temporary_value.data.as_string,
                                            "%" PRIi64,
                                            input_value->data.as_int64);

            if (converstion_canary == NULL) {
                cfl_sds_destroy(temporary_value.data.as_string);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            temporary_value.data.as_bool = CFL_FALSE;

            if (input_value->data.as_int64 != 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
        }
        else if (output_type == CFL_VARIANT_INT) {
            temporary_value.data.as_int64 = input_value->data.as_int64;
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            temporary_value.data.as_double = (double) input_value->data.as_int64;

            /* This conversion could be lossy, we need to determine what we want to
             * do in that case
             */
            if ((int64_t) temporary_value.data.as_double != input_value->data.as_int64) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_ARRAY) {
            temporary_value.data.as_array = cfl_array_create(1);

            if (temporary_value.data.as_array == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            if (cfl_array_append_int64(temporary_value.data.as_array,
                                       input_value->data.as_int64) != 0) {
                cfl_array_destroy(temporary_value.data.as_array);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_DOUBLE) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_sds_create_size(64);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }

            /* We need to fix the wesleys truncation PR to cfl */
            converstion_canary = (char *) cfl_sds_printf(
                                            &temporary_value.data.as_string,
                                            "%.17g",
                                            input_value->data.as_double);

            if (converstion_canary == NULL) {
                cfl_sds_destroy(temporary_value.data.as_string);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            temporary_value.data.as_bool = CFL_FALSE;

            if (input_value->data.as_double != 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
        }
        else if (output_type == CFL_VARIANT_INT) {
            temporary_value.data.as_int64 = (int64_t) round(input_value->data.as_double);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            temporary_value.data.as_double = input_value->data.as_int64;
        }
        else if (output_type == CFL_VARIANT_ARRAY) {
            temporary_value.data.as_array = cfl_array_create(1);

            if (temporary_value.data.as_array == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            if (cfl_array_append_double(temporary_value.data.as_array,
                                        input_value->data.as_double) != 0) {
                cfl_array_destroy(temporary_value.data.as_array);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_KVLIST) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_variant_convert_to_json(input_value);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_ARRAY) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_variant_convert_to_json(input_value);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }

    memcpy(*output_value, &temporary_value, sizeof(struct cfl_variant));

    return FLB_TRUE;
}
