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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_pack.h>
#include <cfl/cfl.h>

#include "cm.h"
#include "cm_utils.h"

#include <math.h>
static int hex_encode(unsigned char *input_buffer, size_t input_length, cfl_sds_t *output_buffer)
{
    const char hex[] = "0123456789abcdef";
    cfl_sds_t  result;
    size_t     index;

    if (cfl_sds_alloc(*output_buffer) <= (input_length * 2)) {
        result = cfl_sds_increase(*output_buffer,
                                  (input_length * 2) -
                                  cfl_sds_alloc(*output_buffer));

        if (result == NULL) {
            return FLB_FALSE;
        }

        *output_buffer = result;
    }

    for (index = 0; index < input_length; index++) {
        (*output_buffer)[index * 2 + 0] = hex[(input_buffer[index] >> 4) & 0xF];
        (*output_buffer)[index * 2 + 1] = hex[(input_buffer[index] >> 0) & 0xF];
    }

    cfl_sds_set_len(*output_buffer, input_length * 2);

    (*output_buffer)[index * 2] = '\0';

    return FLB_TRUE;
}


int cm_utils_hash_transformer(void *context, struct cfl_variant *value)
{
    unsigned char       digest_buffer[32];
    struct cfl_variant *converted_value;
    cfl_sds_t           encoded_hash;
    int                 result;

    if (value == NULL) {
        return FLB_FALSE;
    }

    result = cm_utils_variant_convert(value,
                                      &converted_value,
                                      CFL_VARIANT_STRING);

    if (result != FLB_TRUE) {
        return FLB_FALSE;
    }

    if (cfl_variant_size_get(converted_value) == 0) {
        cfl_variant_destroy(converted_value);
        return FLB_TRUE;
    }

    result = flb_hash_simple(FLB_HASH_SHA256,
                             (unsigned char *) converted_value->data.as_string,
                             cfl_sds_len(converted_value->data.as_string),
                             digest_buffer,
                             sizeof(digest_buffer));

    if (result != FLB_CRYPTO_SUCCESS) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    result = hex_encode(digest_buffer,
                        sizeof(digest_buffer),
                        &converted_value->data.as_string);

    if (result != FLB_TRUE) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    encoded_hash = cfl_sds_create(converted_value->data.as_string);
    cfl_variant_destroy(converted_value);
    if (encoded_hash == NULL) {
        return FLB_FALSE;
    }

    /* NOTE: this part does a manual modification of the variant content */
    if (value->type == CFL_VARIANT_STRING ||
        value->type == CFL_VARIANT_BYTES) {
        if (value->referenced == CFL_FALSE) {
            cfl_sds_destroy(value->data.as_string);
        }
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        cfl_array_destroy(value->data.as_array);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        cfl_kvlist_destroy(value->data.as_kvlist);
    }

    value->type = CFL_VARIANT_STRING;
    value->data.as_string = encoded_hash;
    value->referenced = CFL_FALSE;

    cfl_variant_size_set(value, cfl_sds_len(encoded_hash));

    return FLB_TRUE;
}

cfl_sds_t cm_utils_variant_convert_to_json(struct cfl_variant *value)
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
    MPACK_FREE(data);

    return json_result;
}

int cm_utils_variant_convert(struct cfl_variant *input_value,
                             struct cfl_variant **output_value,
                             int output_type)
{
    int ret;
    int errno_backup;
    int64_t as_int;
    uint64_t as_uint;
    double as_double;
    char buf[64];
    char *str = NULL;
    char *converstion_canary = NULL;
    struct cfl_variant *tmp = NULL;

    errno_backup = errno;

    /* input: string, bytes or reference */
    if (input_value->type == CFL_VARIANT_STRING || input_value->type == CFL_VARIANT_BYTES ||
        input_value->type == CFL_VARIANT_REFERENCE) {

        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            tmp = cfl_variant_create_from_string_s(input_value->data.as_string,
                                                   cfl_variant_size_get(input_value),
                                                   CFL_FALSE);
            if (!tmp) {
                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;

            if (cfl_variant_size_get(input_value) == 4 &&
                strncasecmp(input_value->data.as_string, "true", 4) == 0) {
                as_int = CFL_TRUE;
            }
            else if (cfl_variant_size_get(input_value) == 5 &&
                strncasecmp(input_value->data.as_string, "false", 5) == 0) {
                as_int = CFL_FALSE;
            }

            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            errno = 0;

            if (input_value->referenced) {
                tmp = cfl_variant_create_from_string_s(input_value->data.as_string,
                                                       cfl_variant_size_get(input_value),
                                                       CFL_FALSE);
                if (!tmp) {
                    return CFL_FALSE;
                }
                str = tmp->data.as_string;
            }
            else {
                str = input_value->data.as_string;
            }

            /* signed integer */
            if (str[0] == '-') {
                as_int = strtoimax(str, &converstion_canary, 10);
                if (errno == ERANGE || errno == EINVAL || *converstion_canary != '\0') {
                    errno = errno_backup;
                    if (tmp) {
                        cfl_variant_destroy(tmp);
                    }
                    return CFL_FALSE;
                }

                if (tmp) {
                    cfl_variant_destroy(tmp);
                }

                if (as_int < INT_MIN || as_int > INT_MAX) {
                    return CFL_FALSE;
                }

                tmp = cfl_variant_create_from_int64(as_int);
            }
            else {
                /* unsigned integer */
                as_uint = strtoumax(str, &converstion_canary, 10);
                if (errno == ERANGE || errno == EINVAL || *converstion_canary != '\0') {
                    errno = errno_backup;
                    if (tmp) {
                        cfl_variant_destroy(tmp);
                    }
                    return CFL_FALSE;
                }

                if (tmp) {
                    cfl_variant_destroy(tmp);
                }

                if (as_uint <= INT_MAX) {
                    as_int = (int64_t) as_uint;
                    tmp = cfl_variant_create_from_int64(as_int);
                }
                else if (as_uint <= UINT_MAX) {
                    tmp = cfl_variant_create_from_int64((int64_t) as_uint);
                }
                else {
                    /* out of range for both `int` and `unsigned int` */
                    if (tmp) {
                        cfl_variant_destroy(tmp);
                    }
                    return CFL_FALSE;
                }
            }
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            errno = 0;
            converstion_canary = NULL;

            if (input_value->referenced) {
                tmp = cfl_variant_create_from_string_s(input_value->data.as_string,
                                                       cfl_variant_size_get(input_value),
                                                       CFL_FALSE);
                if (!tmp) {
                    return CFL_FALSE;
                }
                str = tmp->data.as_string;
            }
            else {
                str = input_value->data.as_string;
            }

            as_double = strtod(str, &converstion_canary);
            if (errno == ERANGE) {
                errno = errno_backup;
                if (tmp) {
                    cfl_variant_destroy(tmp);
                }
                return CFL_FALSE;
            }

            if (tmp) {
                cfl_variant_destroy(tmp);
            }

            if (as_double == 0 && converstion_canary == input_value->data.as_string) {
                errno = errno_backup;
                return CFL_FALSE;
            }

            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    /* input: int */
    else if (input_value->type == CFL_VARIANT_INT) {
        if (output_type == CFL_VARIANT_STRING || output_type == CFL_VARIANT_BYTES) {
            ret = snprintf(buf, sizeof(buf), "%" PRIi64, input_value->data.as_int64);
            if (ret < 0 || ret >= sizeof(buf)) {
                return CFL_FALSE;
            }
            tmp = cfl_variant_create_from_string_s(buf, ret, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;
            if (input_value->data.as_int64 != 0) {
                as_int = CFL_TRUE;
            }

            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            tmp = cfl_variant_create_from_int64(input_value->data.as_int64);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            as_double = (double) input_value->data.as_int64;
            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    /* input: uint */
    else if (input_value->type == CFL_VARIANT_UINT) {
        if (output_type == CFL_VARIANT_STRING || output_type == CFL_VARIANT_BYTES) {
            ret = snprintf(buf, sizeof(buf), "%" PRIu64, input_value->data.as_uint64);
            if (ret < 0 || ret >= sizeof(buf)) {
                return CFL_FALSE;
            }
            tmp = cfl_variant_create_from_string_s(buf, ret, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;
            if (input_value->data.as_uint64 != 0) {
                as_int = CFL_TRUE;
            }
            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            tmp = cfl_variant_create_from_uint64(input_value->data.as_uint64);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            as_double = (double) input_value->data.as_int64;
            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_DOUBLE) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            ret = snprintf(buf, sizeof(buf), "%.17g", input_value->data.as_double);
            if (ret < 0 || ret >= sizeof(buf)) {
                return CFL_FALSE;
            }
            tmp = cfl_variant_create_from_string_s(buf, ret, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            as_int = CFL_FALSE;

            if (input_value->data.as_double != 0) {
                as_int = CFL_TRUE;
            }

            tmp = cfl_variant_create_from_bool(as_int);
        }
        else if (output_type == CFL_VARIANT_INT) {
            as_int = (int64_t) round(input_value->data.as_double);
            tmp = cfl_variant_create_from_int64(as_int);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            as_double = input_value->data.as_double;
            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_NULL) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            tmp = cfl_variant_create_from_string_s("null", 4, CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            tmp = cfl_variant_create_from_bool(CFL_FALSE);
        }
        else if (output_type == CFL_VARIANT_INT) {
            tmp = cfl_variant_create_from_int64(0);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            tmp = cfl_variant_create_from_double(0);
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_BOOL) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {

            if (input_value->data.as_bool == CFL_TRUE) {
                tmp = cfl_variant_create_from_string_s("true", 4, CFL_FALSE);
            }
            else {
                tmp = cfl_variant_create_from_string_s("false", 5, CFL_FALSE);
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            tmp = cfl_variant_create_from_bool(input_value->data.as_bool);
        }
        else if (output_type == CFL_VARIANT_INT) {
            as_int = input_value->data.as_bool;
            tmp = cfl_variant_create_from_int64(as_int);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            as_double = (double) input_value->data.as_bool;
            tmp = cfl_variant_create_from_double(as_double);
        }
        else {
            return CFL_FALSE;
        }
    }
    else {
        return CFL_FALSE;
    }

    *output_value = tmp;
    return FLB_TRUE;
}
