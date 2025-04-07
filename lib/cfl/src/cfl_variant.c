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
#include <cfl/cfl_compat.h>

#if defined(__MINGW32__) || defined(__MINGW64__)
#define HEXDUMPFORMAT "%#x"
#else
#define HEXDUMPFORMAT "%p"
#endif

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
        ret = fprintf(fp, "\"%s\"", val->data.as_string);
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
        ret = fprintf(fp, "%lf", val->data.as_double);
        break;
    case CFL_VARIANT_NULL:
        ret = fprintf(fp, "null");
        break;
    case CFL_VARIANT_BYTES:
        size = cfl_sds_len(val->data.as_bytes);
        for (i=0; i<size; i++) {
            ret = fprintf(fp, "%02x", (unsigned char)val->data.as_bytes[i]);
        }
        break;

    case CFL_VARIANT_REFERENCE:
        ret = fprintf(fp, HEXDUMPFORMAT, val->data.as_reference);
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

    instance = cfl_variant_create();
    if (!instance) {
        return NULL;
    }
    instance->referenced = referenced;

    if (referenced) {
        instance->data.as_string = value;
    }
    else {
        instance->data.as_string = cfl_sds_create_len(value, value_size);
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
    return cfl_variant_create_from_string_s(value, strlen(value), CFL_FALSE);
}

struct cfl_variant *cfl_variant_create_from_bytes(char *value, size_t length, int referenced)
{
    struct cfl_variant *instance;

    instance = cfl_variant_create();
    if (!instance){
        return NULL;
    }
    instance->referenced = referenced;

    if (referenced) {
        instance->data.as_bytes = value;
    }
    else {
        instance->data.as_bytes = cfl_sds_create_len(value, length);
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
    var->size = size;
}

size_t cfl_variant_size_get(struct cfl_variant *var)
{
    return var->size;
}
