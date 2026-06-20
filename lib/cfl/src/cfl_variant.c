/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#include <cfl/cfl.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_container.h>
#include <cfl/cfl_compat.h>

#include <limits.h>
#include <math.h>
#if defined(_MSC_VER)
#include <float.h>
#endif

static int double_is_finite(double value)
{
#if defined(_MSC_VER)
    return _finite(value);
#else
    return isfinite(value);
#endif
}

static int print_json_string(FILE *fp, const char *str, size_t len)
{
    size_t i;
    size_t written;
    unsigned char c;
    int ret;

    if (fputc('"', fp) == EOF) {
        return -1;
    }
    written = 1;

    if (str != NULL) {
        for (i = 0; i < len; i++) {
            c = (unsigned char) str[i];

            switch (c) {
            case '"':
                ret = fputs("\\\"", fp);
                written += 2;
                break;
            case '\\':
                ret = fputs("\\\\", fp);
                written += 2;
                break;
            case '\b':
                ret = fputs("\\b", fp);
                written += 2;
                break;
            case '\f':
                ret = fputs("\\f", fp);
                written += 2;
                break;
            case '\n':
                ret = fputs("\\n", fp);
                written += 2;
                break;
            case '\r':
                ret = fputs("\\r", fp);
                written += 2;
                break;
            case '\t':
                ret = fputs("\\t", fp);
                written += 2;
                break;
            default:
                if (c < 0x20) {
                    ret = fprintf(fp, "\\u%04x", c);
                    written += 6;
                }
                else {
                    ret = fputc(c, fp);
                    written++;
                }
                break;
            }

            if (ret < 0) {
                return -1;
            }
        }
    }

    if (fputc('"', fp) == EOF) {
        return -1;
    }
    written++;

    if (written > INT_MAX) {
        return INT_MAX;
    }

    return (int) written;
}

int cfl_variant_print(FILE *fp, struct cfl_variant *val)
{
    int ret = -1;
    size_t size;
    size_t i;

    if (fp == NULL || val == NULL) {
        return -1;
    }

    switch (val->type) {
    case CFL_VARIANT_STRING:
        if (val->data.as_string == NULL && val->size > 0) {
            return -1;
        }
        ret = print_json_string(fp, val->data.as_string, val->size);
        break;
    case CFL_VARIANT_BOOL:
        if (val->data.as_bool) {
            ret = fputs("true",fp);
        }
        else {
            ret = fputs("false", fp);
        }
        break;
    case CFL_VARIANT_INT:
        ret = fprintf(fp, "%" PRId64, val->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        ret = fprintf(fp, "%" PRIu64, val->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        if (!double_is_finite(val->data.as_double)) {
            ret = fputs("null", fp);
        }
        else {
            ret = fprintf(fp, "%lf", val->data.as_double);
        }
        break;
    case CFL_VARIANT_NULL:
        ret = fprintf(fp, "null");
        break;
    case CFL_VARIANT_BYTES:
        if (val->data.as_bytes == NULL && val->size > 0) {
            return -1;
        }

        size = val->size;
        ret = 0;
        for (i = 0; i < size; i++) {
            ret = fprintf(fp, "%02x", (unsigned char)val->data.as_bytes[i]);
            if (ret < 0) {
                return -1;
            }
        }
        break;

    case CFL_VARIANT_REFERENCE:
        ret = fputs("null", fp);
        break;
    case CFL_VARIANT_ARRAY:
        ret = cfl_array_print(fp, val->data.as_array);
        break;

    case CFL_VARIANT_KVLIST:
        ret = cfl_kvlist_print(fp, val->data.as_kvlist);
        break;

    default:
        ret = fputs("!Unknown Type", fp);
    }
    return ret;
}

struct cfl_variant *cfl_variant_create_from_string_s(char *value, size_t value_size, int referenced)
{
    struct cfl_variant *instance;

    if (value == NULL && value_size > 0) {
        return NULL;
    }

    instance = cfl_variant_create();
    if (!instance) {
        return NULL;
    }
    instance->referenced = referenced ? CFL_TRUE : CFL_FALSE;

    if (referenced) {
        instance->data.as_string = value;
    }
    else {
        if (value_size > INT_MAX) {
            free(instance);
            return NULL;
        }

        instance->data.as_string = cfl_sds_create_len(value, (int) value_size);
        if (instance->data.as_string == NULL) {
            free(instance);
            return NULL;
        }

    }
    cfl_variant_size_set(instance, value_size);
    instance->type = CFL_VARIANT_STRING;

    return instance;
}

struct cfl_variant *cfl_variant_create_from_string(char *value)
{
    if (value == NULL) {
        return NULL;
    }

    return cfl_variant_create_from_string_s(value, strlen(value), CFL_FALSE);
}

struct cfl_variant *cfl_variant_create_from_bytes(char *value, size_t length, int referenced)
{
    struct cfl_variant *instance;

    if (value == NULL && length > 0) {
        return NULL;
    }

    instance = cfl_variant_create();
    if (!instance){
        return NULL;
    }
    instance->referenced = referenced ? CFL_TRUE : CFL_FALSE;

    if (referenced) {
        instance->data.as_bytes = value;
    }
    else {
        if (length > INT_MAX) {
            free(instance);
            return NULL;
        }

        instance->data.as_bytes = cfl_sds_create_len(value, (int) length);
        if (instance->data.as_bytes == NULL) {
            free(instance);
            return NULL;
        }
    }
    cfl_variant_size_set(instance, length);
    instance->type = CFL_VARIANT_BYTES;

    return instance;
}

struct cfl_variant *cfl_variant_create_from_bool(int value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        instance->data.as_bool = value;
        instance->type = CFL_VARIANT_BOOL;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_int64(int64_t value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        instance->data.as_int64 = value;
        instance->type = CFL_VARIANT_INT;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_uint64(uint64_t value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        instance->data.as_uint64 = value;
        instance->type = CFL_VARIANT_UINT;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_double(double value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        instance->data.as_double = value;
        instance->type = CFL_VARIANT_DOUBLE;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_null()
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        instance->type = CFL_VARIANT_NULL;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_array(struct cfl_array *value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        if (value != NULL &&
            cfl_container_claim_array(value, instance) != 0) {
            free(instance);
            return NULL;
        }

        instance->data.as_array = value;
        instance->type = CFL_VARIANT_ARRAY;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_kvlist(struct cfl_kvlist *value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        if (value != NULL &&
            cfl_container_claim_kvlist(value, instance) != 0) {
            free(instance);
            return NULL;
        }

        instance->data.as_kvlist = value;
        instance->type = CFL_VARIANT_KVLIST;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create_from_reference(void *value)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (instance != NULL) {
        instance->data.as_reference = value;
        instance->type = CFL_VARIANT_REFERENCE;
    }

    return instance;
}

struct cfl_variant *cfl_variant_create()
{
    struct cfl_variant *instance;

    instance = calloc(1, sizeof(struct cfl_variant));
    if (instance == NULL) {
        cfl_errno();
        return NULL;
    }
    instance->size = 0;

    return instance;
}

void cfl_variant_destroy(struct cfl_variant *instance)
{
    if (!instance) {
        return;
    }

    cfl_container_release_variant(instance);

    if (instance->type == CFL_VARIANT_STRING ||
        instance->type == CFL_VARIANT_BYTES) {
        if (instance->data.as_string != NULL && !instance->referenced) {
            cfl_sds_destroy(instance->data.as_string);
        }
    }
    else if (instance->type == CFL_VARIANT_ARRAY) {
        cfl_array_destroy(instance->data.as_array);
    }
    else if (instance->type == CFL_VARIANT_KVLIST) {
        cfl_kvlist_destroy(instance->data.as_kvlist);
    }

    free(instance);
}

void cfl_variant_size_set(struct cfl_variant *var, size_t size)
{
    if (var == NULL) {
        return;
    }

    var->size = size;
}

size_t cfl_variant_size_get(struct cfl_variant *var)
{
    if (var == NULL) {
        return 0;
    }

    return var->size;
}
