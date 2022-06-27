/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_variant.h>

struct cmt_variant *cmt_variant_create_from_string(char *value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_string = cmt_sds_create(value);

        if (instance->data.as_string == NULL) {
            free(instance);

            instance = NULL;
        }
        else {
            instance->type = CMT_VARIANT_STRING;
        }
    }


    return instance;
}

struct cmt_variant *cmt_variant_create_from_bytes(char *value, size_t length)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_bytes = cmt_sds_create_len(value, length);

        if (instance->data.as_bytes == NULL) {
            free(instance);

            instance = NULL;
        }
        else {
            instance->type = CMT_VARIANT_BYTES;
        }
    }


    return instance;
}

struct cmt_variant *cmt_variant_create_from_bool(int value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_bool = value;
        instance->type = CMT_VARIANT_BOOL;
    }

    return instance;
}

struct cmt_variant *cmt_variant_create_from_int(int value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_int = value;
        instance->type = CMT_VARIANT_INT;
    }

    return instance;
}

struct cmt_variant *cmt_variant_create_from_double(double value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_bool = value;
        instance->type = CMT_VARIANT_DOUBLE;
    }

    return instance;
}

struct cmt_variant *cmt_variant_create_from_array(struct cmt_array *value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_array = value;
        instance->type = CMT_VARIANT_ARRAY;
    }

    return instance;
}

struct cmt_variant *cmt_variant_create_from_kvlist(struct cmt_kvlist *value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_kvlist = value;
        instance->type = CMT_VARIANT_KVLIST;
    }

    return instance;
}

struct cmt_variant *cmt_variant_create_from_reference(void *value)
{
    struct cmt_variant *instance;

    instance = cmt_variant_create();

    if (instance != NULL) {
        instance->data.as_reference = value;
        instance->type = CMT_VARIANT_REFERENCE;
    }

    return instance;
}

struct cmt_variant *cmt_variant_create()
{
    struct cmt_variant *instance;

    instance = calloc(1, sizeof(struct cmt_variant));

    if (instance == NULL) {
        cmt_errno();

        return NULL;
    }

    return instance;
}

void cmt_variant_destroy(struct cmt_variant *instance)
{
    if (instance != NULL) {
        if (instance->type == CMT_VARIANT_STRING ||
            instance->type == CMT_VARIANT_BYTES) {
            if (instance->data.as_string != NULL) {
                cmt_sds_destroy(instance->data.as_string);
            }
        }
        else if (instance->type == CMT_VARIANT_ARRAY) {
            cmt_array_destroy(instance->data.as_array);
        }
        else if (instance->type == CMT_VARIANT_KVLIST) {
            cmt_kvlist_destroy(instance->data.as_kvlist);
        }

        free(instance);
    }
}
