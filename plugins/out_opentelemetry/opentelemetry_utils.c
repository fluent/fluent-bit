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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-otel-proto/fluent-otel.h>

#include "opentelemetry_utils.h"

Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__ArrayValue *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__ArrayValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__array_value__init(value);

        if (entry_count > 0) {
            value->values = \
                flb_calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__AnyValue *));

            if (value->values == NULL) {
                flb_free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

Opentelemetry__Proto__Common__V1__KeyValue *otlp_kvpair_value_initialize()
{
    Opentelemetry__Proto__Common__V1__KeyValue *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value__init(value);
    }

    return value;
}

Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValueList *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValueList));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value_list__init(value);

        if (entry_count > 0) {
            value->values = \
                flb_calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

            if (value->values == NULL) {
                flb_free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

Opentelemetry__Proto__Common__V1__AnyValue *otlp_any_value_initialize(int data_type, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__AnyValue));

    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(value);

    if (data_type == MSGPACK_OBJECT_STR) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_NIL) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET;
    }
    else if (data_type == MSGPACK_OBJECT_BOOLEAN) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_POSITIVE_INTEGER || data_type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_FLOAT32 || data_type == MSGPACK_OBJECT_FLOAT64) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_ARRAY) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
        value->array_value = otlp_array_value_initialize(entry_count);

        if (value->array_value == NULL) {
            flb_free(value);

            value = NULL;
        }
    }
    else if (data_type == MSGPACK_OBJECT_MAP) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;

        value->kvlist_value = otlp_kvlist_value_initialize(entry_count);

        if (value->kvlist_value == NULL) {
            flb_free(value);

            value = NULL;
        }
    }
    else if (data_type == MSGPACK_OBJECT_BIN) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    }
    else {
        flb_free(value);

        value = NULL;
    }

    return value;
}

void otlp_kvarray_destroy(Opentelemetry__Proto__Common__V1__KeyValue **kvarray, size_t entry_count)
{
    size_t index;

    if (kvarray != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            if (kvarray[index] != NULL) {
                otlp_kvpair_destroy(kvarray[index]);
                kvarray[index] = NULL;
            }
        }

        flb_free(kvarray);
    }
}

int otlp_kvarray_append(Opentelemetry__Proto__Common__V1__KeyValue ***base,
                        size_t *base_count,
                        Opentelemetry__Proto__Common__V1__KeyValue **extra,
                        size_t extra_count)
{
    size_t new_count;
    Opentelemetry__Proto__Common__V1__KeyValue **tmp;

    if (extra == NULL || extra_count == 0) {
        return 0;
    }

    new_count = *base_count + extra_count;
    tmp = flb_realloc(*base, new_count * sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    if (!tmp) {
        return -1;
    }

    *base = tmp;
    memcpy(*base + *base_count, extra,
           extra_count * sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    *base_count = new_count;
    flb_free(extra);

    return 0;
}

void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair)
{
    if (kvpair == NULL) {
        return;
    }

    if (kvpair->key != NULL) {
        flb_free(kvpair->key);
    }

    if (kvpair->value != NULL) {
        otlp_any_value_destroy(kvpair->value);
    }

    flb_free(kvpair);
}

void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist)
{
    size_t index;

    if (kvlist != NULL) {
        if (kvlist->values != NULL) {
            for (index = 0 ; index < kvlist->n_values ; index++) {
                otlp_kvpair_destroy(kvlist->values[index]);
            }

            flb_free(kvlist->values);
        }

        flb_free(kvlist);
    }
}

void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    size_t index;

    if (array != NULL) {
        if (array->values != NULL) {
            for (index = 0 ; index < array->n_values ; index++) {
                otlp_any_value_destroy(array->values[index]);
            }

            flb_free(array->values);
        }

        flb_free(array);
    }
}

void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value)
{
    if (value != NULL) {
        if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
            if (value->string_value != NULL) {
                flb_free(value->string_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE) {
            if (value->array_value != NULL) {
                otlp_array_destroy(value->array_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
            if (value->kvlist_value != NULL) {
                otlp_kvlist_destroy(value->kvlist_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
            if (value->bytes_value.data != NULL) {
                flb_free(value->bytes_value.data);
            }
        }

        value->string_value = NULL;

        flb_free(value);
    }
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_boolean_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_BOOLEAN, 0);

    if (result != NULL) {
        result->bool_value = o->via.boolean;
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_integer_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(o->type, 0);

    if (result != NULL) {
        if (o->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            result->int_value = (int64_t) o->via.u64;
        }
        else {
            result->int_value = o->via.i64;
        }
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_float_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(o->type, 0);

    if (result != NULL) {
        result->double_value = o->via.f64;
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_string_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_STR, 0);

    if (result != NULL) {
        result->string_value = flb_strndup(o->via.str.ptr, o->via.str.size);

        if (result->string_value == NULL) {
            otlp_any_value_destroy(result);

            result = NULL;
        }
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_nil_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_NIL, 0);

    if (result != NULL) {
        result->string_value = NULL;
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_bin_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_BIN, 0);

    if (result != NULL) {
        result->bytes_value.len = o->via.bin.size;
        result->bytes_value.data = flb_malloc(o->via.bin.size);

        if (result->bytes_value.data != NULL) {
            memcpy(result->bytes_value.data, o->via.bin.ptr, o->via.bin.size);
        }
        else {
            otlp_any_value_destroy(result);

            result = NULL;
        }

    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_array_to_otlp_any_value(struct msgpack_object *o)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *entry_value;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    size_t                                      index;
    msgpack_object                             *p;

    entry_count = o->via.array.size;
    result = otlp_any_value_initialize(MSGPACK_OBJECT_ARRAY, entry_count);

    p = o->via.array.ptr;

    if (result != NULL) {
        index = 0;

        for (index = 0 ; index < entry_count ; index++) {
            entry_value = msgpack_object_to_otlp_any_value(&p[index]);

            if (entry_value == NULL) {
                otlp_any_value_destroy(result);

                result = NULL;

                break;
            }

            result->array_value->values[index] = entry_value;
        }
    }

    return result;
}

Opentelemetry__Proto__Common__V1__KeyValue *msgpack_kv_to_otlp_any_value(struct msgpack_object_kv *input_pair)
{
    Opentelemetry__Proto__Common__V1__KeyValue *kv;

    kv = otlp_kvpair_value_initialize();
    if (kv == NULL) {
        flb_errno();

        return NULL;
    }

    kv->key = flb_strndup(input_pair->key.via.str.ptr, input_pair->key.via.str.size);
    if (kv->key == NULL) {
        flb_errno();
        flb_free(kv);

        return NULL;
    }

    kv->value = msgpack_object_to_otlp_any_value(&input_pair->val);
    if (kv->value == NULL) {
        flb_free(kv->key);
        flb_free(kv);

        return NULL;
    }

    return kv;
}

Opentelemetry__Proto__Common__V1__KeyValue **msgpack_map_to_otlp_kvarray(struct msgpack_object *o, size_t *entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **result;
    size_t                                       index;
    msgpack_object_kv                           *kv;

    *entry_count = o->via.map.size;
    result = flb_calloc(*entry_count, sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    if (result != NULL) {
        for (index = 0; index < *entry_count; index++) {
            kv = &o->via.map.ptr[index];
            result[index] = msgpack_kv_to_otlp_any_value(kv);
        }
    }
    else {
        *entry_count = 0;
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_map_to_otlp_any_value(struct msgpack_object *o)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    Opentelemetry__Proto__Common__V1__KeyValue *keyvalue;
    size_t                                      index;
    msgpack_object_kv                          *kv;

    entry_count = o->via.map.size;
    result = otlp_any_value_initialize(MSGPACK_OBJECT_MAP, entry_count);

    if (result != NULL) {

        for (index = 0; index < entry_count; index++) {
            kv = &o->via.map.ptr[index];
            keyvalue = msgpack_kv_to_otlp_any_value(kv);
            result->kvlist_value->values[index] = keyvalue;
        }
    }

    return result;
}

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_object_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = NULL;

    switch (o->type) {
        case MSGPACK_OBJECT_NIL:
            result = msgpack_nil_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_BOOLEAN:
            result = msgpack_boolean_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            result = msgpack_integer_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            result = msgpack_float_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_STR:
            result = msgpack_string_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_MAP:
            result = msgpack_map_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_BIN:
            result = msgpack_bin_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_ARRAY:
            result = msgpack_array_to_otlp_any_value(o);
            break;

        default:
            break;
    }

    /* This function will fail if it receives an object with
     * type MSGPACK_OBJECT_EXT
     */

    return result;
}
