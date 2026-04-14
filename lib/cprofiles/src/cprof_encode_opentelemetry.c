/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  =========
 *  Copyright (C) 2024 The CProfiles Authors
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


#include <cprofiles/cprof_encode_opentelemetry.h>
#include <cprofiles/cprof_variant_utils.h>
#include <string.h>

static int is_string_releaseable(char *address)
 {
    return (address != NULL &&
            address != protobuf_c_empty_string);
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_to_otlp_any_value(struct cfl_variant *value);
static inline Opentelemetry__Proto__Common__V1__KeyValue *cfl_variant_kvpair_to_otlp_kvpair(struct cfl_kvpair *input_pair);
static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_kvlist_to_otlp_any_value(struct cfl_variant *value);

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value);
static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair);
static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist);
static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array);

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list, size_t entry_count);

static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair)
{
    if (kvpair != NULL) {
        if (kvpair->key != NULL) {
            free(kvpair->key);
        }

        if (kvpair->value != NULL) {
            otlp_any_value_destroy(kvpair->value);
        }

        free(kvpair);
    }
}

static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist)
{
    size_t index;

    if (kvlist != NULL) {
        if (kvlist->values != NULL) {
            for (index = 0 ; index < kvlist->n_values ; index++) {
                otlp_kvpair_destroy(kvlist->values[index]);
            }

            free(kvlist->values);
        }

        free(kvlist);
    }
}

static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    size_t index;

    if (array != NULL) {
        if (array->values != NULL) {
            for (index = 0 ; index < array->n_values ; index++) {
                otlp_any_value_destroy(array->values[index]);
            }

            free(array->values);
        }

        free(array);
    }
}

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value)
{
    if (value != NULL) {
        if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
            if (value->string_value != NULL) {
                free(value->string_value);
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
                free(value->bytes_value.data);
            }
        }

        free(value);
    }
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **otlp_kvpair_list_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **result;

    result = \
        calloc(entry_count, sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

    return result;
}


static Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__ArrayValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__ArrayValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__array_value__init(value);

        if (entry_count > 0) {
            value->values = \
                calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__AnyValue *));

            if (value->values == NULL) {
                free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValue *otlp_kvpair_value_initialize()
{
    Opentelemetry__Proto__Common__V1__KeyValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value__init(value);
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValueList *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValueList));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value_list__init(value);

        if (entry_count > 0) {
            value->values = \
                calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

            if (value->values == NULL) {
                free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__AnyValue *otlp_any_value_initialize(int data_type, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__AnyValue));

    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(value);

    if (data_type == CFL_VARIANT_STRING) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else if (data_type == CFL_VARIANT_BOOL) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    }
    else if (data_type == CFL_VARIANT_INT) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    }
    else if (data_type == CFL_VARIANT_DOUBLE) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    }
    else if (data_type == CFL_VARIANT_ARRAY) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;

        value->array_value = otlp_array_value_initialize(entry_count);

        if (value->array_value == NULL) {
            free(value);

            value = NULL;
        }
    }
    else if (data_type == CFL_VARIANT_KVLIST) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;

        value->kvlist_value = otlp_kvlist_value_initialize(entry_count);

        if (value->kvlist_value == NULL) {
            free(value);

            value = NULL;
        }
    }
    else if (data_type == CFL_VARIANT_BYTES) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    }
    else if (data_type == CFL_VARIANT_REFERENCE) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else {
        free(value);

        value = NULL;
    }

    return value;
}

static inline Opentelemetry__Proto__Common__V1__KeyValue *cfl_variant_kvpair_to_otlp_kvpair(struct cfl_kvpair *input_pair)
{
    Opentelemetry__Proto__Common__V1__KeyValue *pair;

    pair = otlp_kvpair_value_initialize();

    if (pair != NULL) {
        pair->key = strdup(input_pair->key);

        if (pair->key != NULL) {
            pair->value = cfl_variant_to_otlp_any_value(input_pair->val);

            if (pair->value == NULL) {
                free(pair->key);

                pair->key = NULL;
            }
        }

        if (pair->key == NULL) {
            free(pair);

            pair = NULL;
        }
    }

    return pair;
}

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list, size_t entry_count)
{
    size_t index;

    if (pair_list != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            otlp_kvpair_destroy(pair_list[index]);
        }

        free(pair_list);
    }
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **cfl_kvlist_to_otlp_kvpair_list(struct cfl_kvlist *kvlist)
{
    size_t                                       entry_count;
    Opentelemetry__Proto__Common__V1__KeyValue  *keyvalue;
    struct cfl_list                             *iterator;
    Opentelemetry__Proto__Common__V1__KeyValue **result;
    struct cfl_kvpair                           *kvpair;
    size_t                                       index;

    entry_count = cfl_kvlist_count(kvlist);

    result = otlp_kvpair_list_initialize(entry_count + 1);

    if (result != NULL) {
        index = 0;

        cfl_list_foreach(iterator, &kvlist->list) {
            kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

            keyvalue = cfl_variant_kvpair_to_otlp_kvpair(kvpair);

            if (keyvalue == NULL) {
                otlp_kvpair_list_destroy(result, entry_count);

                result = NULL;

                break;
            }

            result[index++] = keyvalue;
        }
    }

    return result;
}


static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_kvlist_to_otlp_any_value(struct cfl_variant *value)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__KeyValue *keyvalue;
    struct cfl_list                            *iterator;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    struct cfl_kvpair                          *kvpair;
    struct cfl_kvlist                          *kvlist;
    size_t                                      index;


    kvlist = value->data.as_kvlist;

    entry_count = cfl_kvlist_count(kvlist);

    result = otlp_any_value_initialize(CFL_VARIANT_KVLIST, entry_count);

    if (result != NULL) {
        index = 0;

        cfl_list_foreach(iterator, &kvlist->list) {
            kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

            keyvalue = cfl_variant_kvpair_to_otlp_kvpair(kvpair);

            if (keyvalue == NULL) {
                otlp_any_value_destroy(result);

                result = NULL;

                break;
            }

            result->kvlist_value->values[index++] = keyvalue;
        }
    }

    return result;
}


static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_array_to_otlp_any_value(struct cfl_variant *value)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *entry_value;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    struct cfl_array                           *array;
    size_t                                      index;

    array = value->data.as_array;

    entry_count = array->entry_count;

    result = otlp_any_value_initialize(CFL_VARIANT_ARRAY, entry_count);

    if (result != NULL) {
        index = 0;

        for (index = 0 ; index < entry_count ; index++) {
            entry_value = cfl_variant_to_otlp_any_value(cfl_array_fetch_by_index(array, index));

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

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_string_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_STRING, 0);

    if (result != NULL) {
        result->string_value = strdup(value->data.as_string);

        if (result->string_value == NULL) {
            otlp_any_value_destroy(result);

            result = NULL;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_boolean_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_BOOL, 0);

    if (result != NULL) {
        result->bool_value = value->data.as_bool;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_int64_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_INT, 0);

    if (result != NULL) {
        result->int_value = value->data.as_int64;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_double_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_DOUBLE, 0);

    if (result != NULL) {
        result->double_value = value->data.as_double;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_binary_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_BYTES, 0);

    if (result != NULL) {
        result->bytes_value.len = cfl_sds_len(value->data.as_bytes);
        result->bytes_value.data = calloc(result->bytes_value.len, sizeof(char));

        if (result->bytes_value.data) {
            memcpy(result->bytes_value.data, value->data.as_bytes, result->bytes_value.len);
        }
        else {
            otlp_any_value_destroy(result);
            result = NULL;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    if (value->type == CFL_VARIANT_STRING) {
        result = cfl_variant_string_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_BOOL) {
        result = cfl_variant_boolean_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_INT) {
        result = cfl_variant_int64_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_DOUBLE) {
        result = cfl_variant_double_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        result = cfl_variant_array_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        result = cfl_variant_kvlist_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_BYTES) {
        result = cfl_variant_binary_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_REFERENCE) {
        result = cfl_variant_string_to_otlp_any_value(value);
    }
    else {
        result = NULL;
    }

    return result;
}







static void destroy_attribute(
    Opentelemetry__Proto__Common__V1__KeyValue *attribute);

static void destroy_attribute_list(
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list);

static Opentelemetry__Proto__Common__V1__KeyValue **
    initialize_attribute_list(
    size_t element_count);

static void destroy_attribute(Opentelemetry__Proto__Common__V1__KeyValue *attribute)
{
    if (attribute != NULL) {
        if (attribute->value != NULL) {
            if (attribute->value->value_case == \
                OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
                if (is_string_releaseable(attribute->value->string_value)) {
                    free(attribute->value->string_value);
                }
            }

            free(attribute->value);
        }

        if (is_string_releaseable(attribute->key)) {
            free(attribute->key);
        }

        free(attribute);
    }
}

static void destroy_attribute_list(
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list)
{
    size_t element_index;

    if (attribute_list != NULL) {
        for (element_index = 0 ;
             attribute_list[element_index] != NULL ;
             element_index++) {
            destroy_attribute(attribute_list[element_index]);

            attribute_list[element_index] = NULL;
        }

        free(attribute_list);
    }
}

static Opentelemetry__Proto__Common__V1__KeyValue **
    initialize_attribute_list(
    size_t element_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list;

    attribute_list = calloc(element_count + 1,
                            sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

    return attribute_list;
}





static void destroy_value_type(
        Opentelemetry__Proto__Profiles__V1development__ValueType *
            instance)
{
    if (instance != NULL) {
        free(instance);
    }
}

static void destroy_sample(
        Opentelemetry__Proto__Profiles__V1development__Sample *
            instance)
{
    if (instance != NULL) {
        if (instance->values != NULL) {
            free(instance->values);
        }

        if (instance->attribute_indices != NULL) {
            free(instance->attribute_indices);
        }

        if (instance->timestamps_unix_nano != NULL) {
            free(instance->timestamps_unix_nano);
        }

        free(instance);
    }
}


static void destroy_mapping(
        Opentelemetry__Proto__Profiles__V1development__Mapping *
            instance)
{
    if (instance != NULL) {
        if (instance->attribute_indices != NULL) {
            free(instance->attribute_indices);
        }

        free(instance);
    }
}


static void destroy_resource(
        Opentelemetry__Proto__Resource__V1__Resource *
            instance)
{
    if (instance != NULL) {
        destroy_attribute_list(instance->attributes);

        free(instance);
    }
}

static void destroy_line(
        Opentelemetry__Proto__Profiles__V1development__Line *
            instance)
{
    if (instance != NULL) {
        free(instance);
    }
}

static void destroy_link(
        Opentelemetry__Proto__Profiles__V1development__Link *
            instance)
{
    if (instance != NULL) {
        if (instance->trace_id.data != NULL) {
            if (is_string_releaseable((cfl_sds_t) instance->trace_id.data)) {
                cfl_sds_destroy((cfl_sds_t) instance->trace_id.data);
            }
        }

        if (instance->span_id.data != NULL) {
            if (is_string_releaseable((cfl_sds_t) instance->span_id.data)) {
                cfl_sds_destroy((cfl_sds_t) instance->span_id.data);
            }
        }

        free(instance);
    }
}


static void destroy_location(
        Opentelemetry__Proto__Profiles__V1development__Location *
            instance)
{
    size_t index;

    if (instance != NULL) {
        if (instance->lines != NULL) {
            for (index = 0 ; index < instance->n_lines ; index++) {
                destroy_line(instance->lines[index]);
            }

            free(instance->lines);
        }

        if (instance->attribute_indices != NULL) {
            free(instance->attribute_indices);
        }

        free(instance);
    }
}

static void destroy_keyvalueandunit(
        Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit *
            instance)
{
    if (instance != NULL) {
        if (instance->value != NULL) {
            otlp_any_value_destroy(instance->value);
        }
        free(instance);
    }
}

static void destroy_function(
        Opentelemetry__Proto__Profiles__V1development__Function *
            instance)
{
    if (instance != NULL) {
        free(instance);
    }
}

static void destroy_instrumentation_scope(
        Opentelemetry__Proto__Common__V1__InstrumentationScope *
            instance)
{
    if (instance != NULL) {
        destroy_attribute_list(instance->attributes);

        if (instance->name != NULL) {
            if (is_string_releaseable(instance->name)) {
                cfl_sds_destroy(instance->name);
            }
        }

        if (instance->version != NULL) {
            if (is_string_releaseable(instance->version)) {
                cfl_sds_destroy(instance->version);
            }
        }

        free(instance);
    }
}

static void destroy_profile(
        Opentelemetry__Proto__Profiles__V1development__Profile *
            instance)
{
    size_t index;

    if (instance != NULL) {
        if (instance->sample_type != NULL) {
            destroy_value_type(instance->sample_type);
        }

        if (instance->samples != NULL) {
            for (index = 0 ; index < instance->n_samples ; index++) {
                destroy_sample(instance->samples[index]);
            }
            free(instance->samples);
        }

        if (instance->period_type != NULL) {
            destroy_value_type(instance->period_type);
        }

        if (instance->attribute_indices != NULL) {
            free(instance->attribute_indices);
        }

        if (instance->profile_id.data != NULL && is_string_releaseable((char *)instance->profile_id.data)) {
            free(instance->profile_id.data);
        }

        if (instance->original_payload_format != NULL && is_string_releaseable(instance->original_payload_format)) {
            free(instance->original_payload_format);
        }

        if (instance->original_payload.data != NULL && is_string_releaseable((char *)instance->original_payload.data)) {
            free(instance->original_payload.data);
        }

        free(instance);
    }
}

static void destroy_scope_profiles(
        Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *
            instance)
{
    size_t index;

    if (instance != NULL) {
        if (instance->scope != NULL) {
            destroy_instrumentation_scope(instance->scope);
        }

        if (instance->profiles != NULL) {
            for (index = 0 ; index < instance->n_profiles ; index++) {
                destroy_profile(instance->profiles[index]);
            }

            free(instance->profiles);
        }

        if (instance->schema_url != NULL) {
            if (is_string_releaseable(instance->schema_url)) {
                cfl_sds_destroy(instance->schema_url);
            }
        }

        free(instance);
    }
}
static void destroy_resource_profiles(
        Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *
            instance)
{
    size_t index;

    if (instance != NULL) {
        if (instance->resource != NULL) {
            destroy_resource(instance->resource);
        }

        if (instance->scope_profiles != NULL) {
            for (index = 0 ; index < instance->n_scope_profiles ; index++) {
                destroy_scope_profiles(instance->scope_profiles[index]);
            }

            free(instance->scope_profiles);
        }

        if (instance->schema_url != NULL) {
            if (is_string_releaseable(instance->schema_url)) {
                cfl_sds_destroy(instance->schema_url);
            }
        }

        free(instance);
    }
}

static void destroy_stack(Opentelemetry__Proto__Profiles__V1development__Stack *instance)
{
    if (instance != NULL) {
        if (instance->location_indices != NULL) {
            free(instance->location_indices);
        }
        free(instance);
    }
}

static void destroy_profiles_dictionary(
        Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict)
{
    size_t index;

    if (dict == NULL) {
        return;
    }
    if (dict->mapping_table != NULL) {
        for (index = 0; index < dict->n_mapping_table; index++) {
            destroy_mapping(dict->mapping_table[index]);
        }
        free(dict->mapping_table);
    }
    if (dict->location_table != NULL) {
        for (index = 0; index < dict->n_location_table; index++) {
            destroy_location(dict->location_table[index]);
        }
        free(dict->location_table);
    }
    if (dict->function_table != NULL) {
        for (index = 0; index < dict->n_function_table; index++) {
            destroy_function(dict->function_table[index]);
        }
        free(dict->function_table);
    }
    if (dict->link_table != NULL) {
        for (index = 0; index < dict->n_link_table; index++) {
            destroy_link(dict->link_table[index]);
        }
        free(dict->link_table);
    }
    if (dict->string_table != NULL) {
        for (index = 0; index < dict->n_string_table; index++) {
            if (dict->string_table[index] != NULL) {
                cfl_sds_destroy((cfl_sds_t) dict->string_table[index]);
            }
        }
        free(dict->string_table);
    }
    if (dict->attribute_table != NULL) {
        for (index = 0; index < dict->n_attribute_table; index++) {
            destroy_keyvalueandunit(dict->attribute_table[index]);
        }
        free(dict->attribute_table);
    }
    if (dict->stack_table != NULL) {
        for (index = 0; index < dict->n_stack_table; index++) {
            destroy_stack(dict->stack_table[index]);
        }
        free(dict->stack_table);
    }
    free(dict);
}

static void destroy_export_profiles_service_request(
        Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *
            instance)
{
    size_t index;

    if (instance != NULL) {
        if (instance->resource_profiles != NULL) {
            for (index = 0 ; index < instance->n_resource_profiles ; index++) {
                destroy_resource_profiles(instance->resource_profiles[index]);
            }

            free(instance->resource_profiles);
        }

        if (instance->dictionary != NULL) {
            destroy_profiles_dictionary(instance->dictionary);
        }

        free(instance);
    }
}

/*
 * Per-profile encoding state: maps profile-local indices to dictionary indices.
 * Used when packing so ValueType.type_strindex, Sample.stack_index, etc. point into the dictionary.
 */
struct profile_encoding_state {
    int32_t *string_map;           /* profile string_table index -> dict string index */
    size_t   string_map_count;
    int32_t *mapping_map;          /* profile mapping index -> dict mapping index */
    size_t   mapping_map_count;
    int32_t *function_map;
    size_t   function_map_count;
    int32_t *location_map;
    size_t   location_map_count;
    int32_t *link_map;
    size_t   link_map_count;
    int32_t *stack_index_by_sample; /* sample index -> dict stack index */
    size_t   sample_count;
};

static void free_profile_encoding_state(struct profile_encoding_state *s)
{
    if (s == NULL) {
        return;
    }
    free(s->string_map);
    free(s->mapping_map);
    free(s->function_map);
    free(s->location_map);
    free(s->link_map);
    free(s->stack_index_by_sample);
}

/* Internal context passed through pack_* to access dictionary encoding state per profile */
typedef struct {
    struct cprof_opentelemetry_encoding_context *pub;
    struct profile_encoding_state               *encoding_states;
    size_t                                       encoding_states_count;
    size_t                                       current_profile_index;
} encoder_internal_ctx_t;

/* Find or add string in dictionary; returns dict string index. */
static int32_t dict_add_string(
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict,
    const char *str)
{
    size_t i;
    char  *dup;

    if (str == NULL) {
        str = "";
    }
    for (i = 0; i < dict->n_string_table; i++) {
        if (dict->string_table[i] != NULL && strcmp(dict->string_table[i], str) == 0) {
            return (int32_t) i;
        }
    }
    dup = cfl_sds_create(str);
    if (dup == NULL) {
        return -1;
    }
    dict->string_table = realloc(dict->string_table,
                                 (dict->n_string_table + 1) * sizeof(char *));
    if (dict->string_table == NULL) {
        cfl_sds_destroy(dup);
        return -1;
    }
    dict->string_table[dict->n_string_table] = dup;
    return (int32_t) dict->n_string_table++;
}

/* Find or add stack (location_indices) in dictionary; returns dict stack index. */
static int32_t dict_add_stack(
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict,
    const int32_t *location_indices,
    size_t n_location_indices)
{
    size_t                                                 i;
    size_t                                                 j;
    Opentelemetry__Proto__Profiles__V1development__Stack **stacks;
    Opentelemetry__Proto__Profiles__V1development__Stack  *stack;

    for (i = 0; i < dict->n_stack_table; i++) {
        if (dict->stack_table[i]->n_location_indices != n_location_indices) {
            continue;
        }
        for (j = 0; j < n_location_indices; j++) {
            if (dict->stack_table[i]->location_indices[j] != location_indices[j]) {
                break;
            }
        }
        if (j == n_location_indices) {
            return (int32_t) i;
        }
    }
    stack = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Stack));
    if (stack == NULL) {
        return -1;
    }
    opentelemetry__proto__profiles__v1development__stack__init(stack);
    if (n_location_indices > 0) {
        stack->location_indices = malloc(n_location_indices * sizeof(int32_t));
        if (stack->location_indices == NULL) {
            free(stack);
            return -1;
        }
        memcpy(stack->location_indices, location_indices, n_location_indices * sizeof(int32_t));
        stack->n_location_indices = n_location_indices;
    }
    stacks = realloc(dict->stack_table,
                     (dict->n_stack_table + 1) * sizeof(Opentelemetry__Proto__Profiles__V1development__Stack *));
    if (stacks == NULL) {
        free(stack->location_indices);
        free(stack);
        return -1;
    }
    dict->stack_table = stacks;
    dict->stack_table[dict->n_stack_table] = stack;
    return (int32_t) dict->n_stack_table++;
}

/* Build OTLP Mapping from cprof_mapping; caller must destroy. Uses string_map for filename_strindex. */
static Opentelemetry__Proto__Profiles__V1development__Mapping *
dict_build_mapping(struct cprof_mapping *m,
                  const int32_t *string_map,
                  size_t string_map_count)
{
    Opentelemetry__Proto__Profiles__V1development__Mapping *otlp;

    otlp = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Mapping));
    if (otlp == NULL) {
        return NULL;
    }
    opentelemetry__proto__profiles__v1development__mapping__init(otlp);
    otlp->memory_start = m->memory_start;
    otlp->memory_limit = m->memory_limit;
    otlp->file_offset = m->file_offset;
    if (m->filename >= 0 && (size_t)m->filename < string_map_count) {
        otlp->filename_strindex = string_map[m->filename];
    }
    else {
        otlp->filename_strindex = 0;
    }
    /* attribute_indices reference dict attribute_table; leave 0 for now */
    return otlp;
}

/* Compare two OTLP Mappings (excluding attribute_indices). */
static int mapping_equal(const Opentelemetry__Proto__Profiles__V1development__Mapping *a,
                         const Opentelemetry__Proto__Profiles__V1development__Mapping *b)
{
    return a->memory_start == b->memory_start &&
           a->memory_limit == b->memory_limit &&
           a->file_offset == b->file_offset &&
           a->filename_strindex == b->filename_strindex;
}

/* Find or add Mapping in dictionary; returns dict mapping index or -1 on error. */
static int32_t dict_add_mapping(
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict,
    struct cprof_mapping *m,
    const int32_t *string_map,
    size_t string_map_count)
{
    Opentelemetry__Proto__Profiles__V1development__Mapping *otlp;
    Opentelemetry__Proto__Profiles__V1development__Mapping **tab;
    size_t i;

    otlp = dict_build_mapping(m, string_map, string_map_count);
    if (otlp == NULL) {
        return -1;
    }
    for (i = 0; i < dict->n_mapping_table; i++) {
        if (mapping_equal(dict->mapping_table[i], otlp)) {
            destroy_mapping(otlp);
            return (int32_t) i;
        }
    }
    tab = realloc(dict->mapping_table,
                  (dict->n_mapping_table + 1) * sizeof(Opentelemetry__Proto__Profiles__V1development__Mapping *));
    if (tab == NULL) {
        destroy_mapping(otlp);
        return -1;
    }
    dict->mapping_table = tab;
    dict->mapping_table[dict->n_mapping_table] = otlp;
    return (int32_t) dict->n_mapping_table++;
}

/* Build OTLP Function from cprof_function; caller must destroy. */
static Opentelemetry__Proto__Profiles__V1development__Function *
dict_build_function(struct cprof_function *f,
                    const int32_t *string_map,
                    size_t string_map_count)
{
    Opentelemetry__Proto__Profiles__V1development__Function *otlp;

    otlp = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Function));
    if (otlp == NULL) {
        return NULL;
    }
    opentelemetry__proto__profiles__v1development__function__init(otlp);
    if (f->name >= 0 && (size_t)f->name < string_map_count) {
        otlp->name_strindex = string_map[f->name];
    }
    else {
        otlp->name_strindex = 0;
    }
    if (f->system_name >= 0 && (size_t)f->system_name < string_map_count) {
        otlp->system_name_strindex = string_map[f->system_name];
    }
    else {
        otlp->system_name_strindex = 0;
    }
    if (f->filename >= 0 && (size_t)f->filename < string_map_count) {
        otlp->filename_strindex = string_map[f->filename];
    }
    else {
        otlp->filename_strindex = 0;
    }
    otlp->start_line = f->start_line;
    return otlp;
}

static int function_equal(const Opentelemetry__Proto__Profiles__V1development__Function *a,
                          const Opentelemetry__Proto__Profiles__V1development__Function *b)
{
    return a->name_strindex == b->name_strindex &&
           a->system_name_strindex == b->system_name_strindex &&
           a->filename_strindex == b->filename_strindex &&
           a->start_line == b->start_line;
}

static int32_t dict_add_function(
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict,
    struct cprof_function *f,
    const int32_t *string_map,
    size_t string_map_count)
{
    Opentelemetry__Proto__Profiles__V1development__Function *otlp;
    Opentelemetry__Proto__Profiles__V1development__Function **tab;
    size_t i;

    otlp = dict_build_function(f, string_map, string_map_count);
    if (otlp == NULL) {
        return -1;
    }
    for (i = 0; i < dict->n_function_table; i++) {
        if (function_equal(dict->function_table[i], otlp)) {
            destroy_function(otlp);
            return (int32_t) i;
        }
    }
    tab = realloc(dict->function_table,
                  (dict->n_function_table + 1) * sizeof(Opentelemetry__Proto__Profiles__V1development__Function *));
    if (tab == NULL) {
        destroy_function(otlp);
        return -1;
    }
    dict->function_table = tab;
    dict->function_table[dict->n_function_table] = otlp;
    return (int32_t) dict->n_function_table++;
}

static Opentelemetry__Proto__Profiles__V1development__Location *initialize_location(size_t line_count, size_t attribute_count);
static Opentelemetry__Proto__Profiles__V1development__Link *initialize_link(void);

/* Build OTLP Location from cprof_location; uses mapping_map and function_map for indices. Caller must destroy. */
static Opentelemetry__Proto__Profiles__V1development__Location *
dict_build_location(struct cprof_location *loc,
                    const int32_t *mapping_map,
                    size_t mapping_map_count,
                    const int32_t *function_map,
                    size_t function_map_count)
{
    Opentelemetry__Proto__Profiles__V1development__Location *otlp;
    struct cfl_list *line_iter;
    struct cprof_line *line;
    size_t n_lines;
    size_t idx;

    n_lines = cfl_list_size(&loc->lines);
    otlp = initialize_location(n_lines, 0);
    if (otlp == NULL) {
        return NULL;
    }
    if (loc->mapping_index < mapping_map_count) {
        otlp->mapping_index = mapping_map[loc->mapping_index];
    }
    else {
        otlp->mapping_index = 0;
    }
    otlp->address = loc->address;

    idx = 0;
    cfl_list_foreach(line_iter, &loc->lines) {
        line = cfl_list_entry(line_iter, struct cprof_line, _head);
        otlp->lines[idx] = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Line));
        if (otlp->lines[idx] == NULL) {
            destroy_location(otlp);
            return NULL;
        }
        opentelemetry__proto__profiles__v1development__line__init(otlp->lines[idx]);
        if ((size_t)line->function_index < function_map_count) {
            otlp->lines[idx]->function_index = function_map[line->function_index];
        }
        else {
            otlp->lines[idx]->function_index = 0;
        }
        otlp->lines[idx]->line = line->line;
        otlp->lines[idx]->column = line->column;
        idx++;
    }

    return otlp;
}

static int location_equal(const Opentelemetry__Proto__Profiles__V1development__Location *a,
                          const Opentelemetry__Proto__Profiles__V1development__Location *b)
{
    size_t i;

    if (a->mapping_index != b->mapping_index || a->address != b->address || a->n_lines != b->n_lines) {
        return 0;
    }
    for (i = 0; i < a->n_lines; i++) {
        if (a->lines[i]->function_index != b->lines[i]->function_index ||
            a->lines[i]->line != b->lines[i]->line ||
            a->lines[i]->column != b->lines[i]->column) {
            return 0;
        }
    }
    return 1;
}

static int32_t dict_add_location(
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict,
    struct cprof_location *loc,
    const int32_t *mapping_map,
    size_t mapping_map_count,
    const int32_t *function_map,
    size_t function_map_count)
{
    Opentelemetry__Proto__Profiles__V1development__Location *otlp;
    Opentelemetry__Proto__Profiles__V1development__Location **tab;
    size_t i;

    otlp = dict_build_location(loc, mapping_map, mapping_map_count, function_map, function_map_count);
    if (otlp == NULL) {
        return -1;
    }
    for (i = 0; i < dict->n_location_table; i++) {
        if (location_equal(dict->location_table[i], otlp)) {
            destroy_location(otlp);
            return (int32_t) i;
        }
    }
    tab = realloc(dict->location_table,
                  (dict->n_location_table + 1) * sizeof(Opentelemetry__Proto__Profiles__V1development__Location *));
    if (tab == NULL) {
        destroy_location(otlp);
        return -1;
    }
    dict->location_table = tab;
    dict->location_table[dict->n_location_table] = otlp;
    return (int32_t) dict->n_location_table++;
}

/* Build OTLP Link from cprof_link; caller must destroy. */
static Opentelemetry__Proto__Profiles__V1development__Link *
dict_build_link(struct cprof_link *l)
{
    Opentelemetry__Proto__Profiles__V1development__Link *otlp;

    otlp = initialize_link();
    if (otlp == NULL) {
        return NULL;
    }
    otlp->trace_id.data = (uint8_t *) cfl_sds_create_len((const char *) l->trace_id, sizeof(l->trace_id));
    if (otlp->trace_id.data == NULL) {
        destroy_link(otlp);
        return NULL;
    }
    otlp->trace_id.len = sizeof(l->trace_id);
    otlp->span_id.data = (uint8_t *) cfl_sds_create_len((const char *) l->span_id, sizeof(l->span_id));
    if (otlp->span_id.data == NULL) {
        destroy_link(otlp);
        return NULL;
    }
    otlp->span_id.len = sizeof(l->span_id);
    return otlp;
}

static int link_equal(const Opentelemetry__Proto__Profiles__V1development__Link *a,
                      const Opentelemetry__Proto__Profiles__V1development__Link *b)
{
    if (a->trace_id.len != b->trace_id.len || a->span_id.len != b->span_id.len) {
        return 0;
    }
    return memcmp(a->trace_id.data, b->trace_id.data, a->trace_id.len) == 0 &&
           memcmp(a->span_id.data, b->span_id.data, a->span_id.len) == 0;
}

static int32_t dict_add_link(
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict,
    struct cprof_link *l)
{
    Opentelemetry__Proto__Profiles__V1development__Link *otlp;
    Opentelemetry__Proto__Profiles__V1development__Link **tab;
    size_t i;

    otlp = dict_build_link(l);
    if (otlp == NULL) {
        return -1;
    }
    for (i = 0; i < dict->n_link_table; i++) {
        if (link_equal(dict->link_table[i], otlp)) {
            destroy_link(otlp);
            return (int32_t) i;
        }
    }
    tab = realloc(dict->link_table,
                  (dict->n_link_table + 1) * sizeof(Opentelemetry__Proto__Profiles__V1development__Link *));
    if (tab == NULL) {
        destroy_link(otlp);
        return -1;
    }
    dict->link_table = tab;
    dict->link_table[dict->n_link_table] = otlp;
    return (int32_t) dict->n_link_table++;
}

/*
 * Build ProfilesDictionary and per-profile encoding states from the full cprof tree.
 * Caller must free encoding_states (and each state's arrays) and destroy the dictionary.
 */
static int build_profiles_dictionary(
    struct cprof *cprof,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary **out_dict,
    struct profile_encoding_state **out_states,
    size_t *out_state_count)
{
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dict;
    struct cfl_list                                                   *rp_iter;
    struct cfl_list                                                   *sp_iter;
    struct cfl_list                                                   *prof_iter;
    struct cfl_list                                                   *map_iter;
    struct cfl_list                                                   *func_iter;
    struct cfl_list                                                   *loc_iter;
    struct cfl_list                                                   *link_iter;
    struct cfl_list                                                   *sample_iter;
    struct cprof_resource_profiles                                    *rp;
    struct cprof_scope_profiles                                       *sp;
    struct cprof_profile                                              *profile;
    struct cprof_mapping                                              *cprof_mapping;
    struct cprof_function                                             *cprof_func;
    struct cprof_location                                             *cprof_loc;
    struct cprof_link                                                *cprof_link;
    struct cprof_sample                                              *sample;
    struct profile_encoding_state                                     *states;
    size_t                                                             state_count;
    size_t                                                             state_idx;
    size_t                                                             i;
    size_t                                                             j;
    size_t                                                             n_loc;
    uint64_t                                                           loc_idx;
    int32_t                                                            si;
    int32_t                                                            loc_indices_buf[256];
    int32_t                                                           *loc_indices;

    state_count = 0;
    cfl_list_foreach(rp_iter, &cprof->profiles) {
        rp = cfl_list_entry(rp_iter, struct cprof_resource_profiles, _head);
        cfl_list_foreach(sp_iter, &rp->scope_profiles) {
            sp = cfl_list_entry(sp_iter, struct cprof_scope_profiles, _head);
            state_count += cfl_list_size(&sp->profiles);
        }
    }
    if (state_count == 0) {
        *out_dict = NULL;
        *out_states = NULL;
        *out_state_count = 0;
        return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
    }

    dict = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary));
    if (dict == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    opentelemetry__proto__profiles__v1development__profiles_dictionary__init(dict);

    /* string_table[0] = "" (required) */
    dict->string_table = malloc(sizeof(char *));
    if (dict->string_table == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->string_table[0] = cfl_sds_create("");
    if (dict->string_table[0] == NULL) {
        free(dict->string_table);
        free(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->n_string_table = 1;

    /* stack_table[0] = zero Stack (required) */
    dict->stack_table = malloc(sizeof(Opentelemetry__Proto__Profiles__V1development__Stack *));
    if (dict->stack_table == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->stack_table[0] = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Stack));
    if (dict->stack_table[0] == NULL) {
        free(dict->stack_table);
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    opentelemetry__proto__profiles__v1development__stack__init(dict->stack_table[0]);
    dict->n_stack_table = 1;

    /* mapping_table[0] = zero Mapping (required) */
    dict->mapping_table = malloc(sizeof(Opentelemetry__Proto__Profiles__V1development__Mapping *));
    if (dict->mapping_table == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->mapping_table[0] = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Mapping));
    if (dict->mapping_table[0] == NULL) {
        free(dict->mapping_table);
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    opentelemetry__proto__profiles__v1development__mapping__init(dict->mapping_table[0]);
    dict->n_mapping_table = 1;

    /* location_table[0] = zero Location (required) */
    dict->location_table = malloc(sizeof(Opentelemetry__Proto__Profiles__V1development__Location *));
    if (dict->location_table == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->location_table[0] = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Location));
    if (dict->location_table[0] == NULL) {
        free(dict->location_table);
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    opentelemetry__proto__profiles__v1development__location__init(dict->location_table[0]);
    dict->n_location_table = 1;

    /* function_table[0] = zero Function (required) */
    dict->function_table = malloc(sizeof(Opentelemetry__Proto__Profiles__V1development__Function *));
    if (dict->function_table == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->function_table[0] = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Function));
    if (dict->function_table[0] == NULL) {
        free(dict->function_table);
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    opentelemetry__proto__profiles__v1development__function__init(dict->function_table[0]);
    dict->n_function_table = 1;

    /* link_table[0] = zero Link (required) */
    dict->link_table = malloc(sizeof(Opentelemetry__Proto__Profiles__V1development__Link *));
    if (dict->link_table == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    dict->link_table[0] = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Link));
    if (dict->link_table[0] == NULL) {
        free(dict->link_table);
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    opentelemetry__proto__profiles__v1development__link__init(dict->link_table[0]);
    dict->n_link_table = 1;

    states = calloc(state_count, sizeof(struct profile_encoding_state));
    if (states == NULL) {
        destroy_profiles_dictionary(dict);
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    state_idx = 0;

    cfl_list_foreach(rp_iter, &cprof->profiles) {
        rp = cfl_list_entry(rp_iter, struct cprof_resource_profiles, _head);
        cfl_list_foreach(sp_iter, &rp->scope_profiles) {
            sp = cfl_list_entry(sp_iter, struct cprof_scope_profiles, _head);
            cfl_list_foreach(prof_iter, &sp->profiles) {
                profile = cfl_list_entry(prof_iter, struct cprof_profile, _head);
                struct profile_encoding_state *st = &states[state_idx];

                /* string_map: profile string_table index -> dict index */
                st->string_map_count = profile->string_table_count;
                if (st->string_map_count > 0) {
                    st->string_map = malloc(st->string_map_count * sizeof(int32_t));
                    if (st->string_map == NULL) {
                        goto fail;
                    }
                    for (i = 0; i < st->string_map_count; i++) {
                        si = dict_add_string(dict,
                            profile->string_table[i] ? profile->string_table[i] : "");
                        if (si < 0) {
                            goto fail;
                        }
                        st->string_map[i] = si;
                    }
                }

                /* stack_index_by_sample: for each sample, resolve location_index[] to dict stack */
                st->sample_count = cfl_list_size(&profile->samples);
                if (st->sample_count > 0) {
                    st->stack_index_by_sample = malloc(st->sample_count * sizeof(int32_t));
                    if (st->stack_index_by_sample == NULL) {
                        goto fail;
                    }
                }

                /* Build mapping_table, function_table, location_table, link_table entries and
                 * per-profile maps (profile index -> dict index) so stacks reference real locations. */
                st->location_map_count = cfl_list_size(&profile->locations);
                st->mapping_map_count = cfl_list_size(&profile->mappings);
                st->function_map_count = cfl_list_size(&profile->functions);
                st->link_map_count = cfl_list_size(&profile->link_table);

                if (st->mapping_map_count > 0) {
                    st->mapping_map = malloc(st->mapping_map_count * sizeof(int32_t));
                    if (st->mapping_map == NULL) {
                        goto fail;
                    }
                    i = 0;
                    cfl_list_foreach(map_iter, &profile->mappings) {
                        cprof_mapping = cfl_list_entry(map_iter, struct cprof_mapping, _head);
                        si = dict_add_mapping(dict, cprof_mapping, st->string_map, st->string_map_count);
                        if (si < 0) {
                            goto fail;
                        }
                        st->mapping_map[i++] = si;
                    }
                }
                if (st->function_map_count > 0) {
                    st->function_map = malloc(st->function_map_count * sizeof(int32_t));
                    if (st->function_map == NULL) {
                        goto fail;
                    }
                    i = 0;
                    cfl_list_foreach(func_iter, &profile->functions) {
                        cprof_func = cfl_list_entry(func_iter, struct cprof_function, _head);
                        si = dict_add_function(dict, cprof_func, st->string_map, st->string_map_count);
                        if (si < 0) {
                            goto fail;
                        }
                        st->function_map[i++] = si;
                    }
                }
                if (st->location_map_count > 0) {
                    st->location_map = malloc(st->location_map_count * sizeof(int32_t));
                    if (st->location_map == NULL) {
                        goto fail;
                    }
                    i = 0;
                    cfl_list_foreach(loc_iter, &profile->locations) {
                        cprof_loc = cfl_list_entry(loc_iter, struct cprof_location, _head);
                        si = dict_add_location(dict, cprof_loc,
                                              st->mapping_map, st->mapping_map_count,
                                              st->function_map, st->function_map_count);
                        if (si < 0) {
                            goto fail;
                        }
                        st->location_map[i++] = si;
                    }
                }
                if (st->link_map_count > 0) {
                    st->link_map = malloc(st->link_map_count * sizeof(int32_t));
                    if (st->link_map == NULL) {
                        goto fail;
                    }
                    i = 0;
                    cfl_list_foreach(link_iter, &profile->link_table) {
                        cprof_link = cfl_list_entry(link_iter, struct cprof_link, _head);
                        si = dict_add_link(dict, cprof_link);
                        if (si < 0) {
                            goto fail;
                        }
                        st->link_map[i++] = si;
                    }
                }

                /* Build stack_index_by_sample: map each sample's location_index[] to dict stack */
                j = 0;
                cfl_list_foreach(sample_iter, &profile->samples) {
                    loc_indices = loc_indices_buf;
                    sample = cfl_list_entry(sample_iter, struct cprof_sample, _head);
                    n_loc = sample->location_index_count;
                    if (n_loc == 0) {
                        si = 0; /* zero stack */
                    }
                    else {
                        if (n_loc > 256) {
                            loc_indices = malloc(n_loc * sizeof(int32_t));
                            if (loc_indices == NULL) {
                                goto fail;
                            }
                        }
                        for (i = 0; i < n_loc; i++) {
                            loc_idx = sample->location_index[i];
                            loc_indices[i] = (loc_idx < st->location_map_count)
                                ? st->location_map[loc_idx] : 0;
                        }
                        si = dict_add_stack(dict, loc_indices, n_loc);
                        if (n_loc > 256) {
                            free(loc_indices);
                        }
                        if (si < 0) {
                            goto fail;
                        }
                    }
                    st->stack_index_by_sample[j++] = si;
                }

                state_idx++;
            }
        }
    }

    *out_dict = dict;
    *out_states = states;
    *out_state_count = state_count;
    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
fail:
    for (i = 0; i < state_idx; i++) {
        free_profile_encoding_state(&states[i]);
    }
    free(states);
    destroy_profiles_dictionary(dict);
    return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
}

static
    Opentelemetry__Proto__Profiles__V1development__ValueType *
        initialize_value_type() {
    Opentelemetry__Proto__Profiles__V1development__ValueType *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__ValueType));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__value_type__init(instance);

    return instance;
}



static
    Opentelemetry__Proto__Profiles__V1development__Sample *
        initialize_sample(
            size_t value_count,
            size_t attributes_count,
            size_t timestamps_count) {
    Opentelemetry__Proto__Profiles__V1development__Sample *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Sample));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__sample__init(instance);

    if (value_count > 0) {
        instance->values = calloc(value_count, sizeof(int64_t));

        if (instance->values == NULL) {
            destroy_sample(instance);

            return NULL;
        }

        instance->n_values = value_count;
    }

    if (attributes_count > 0) {
        instance->attribute_indices = calloc(attributes_count, sizeof(int32_t));

        if (instance->attribute_indices == NULL) {
            destroy_sample(instance);

            return NULL;
        }

        instance->n_attribute_indices = attributes_count;
    }

    if (timestamps_count > 0) {
        instance->timestamps_unix_nano = calloc(timestamps_count, sizeof(uint64_t));

        if (instance->timestamps_unix_nano == NULL) {
            destroy_sample(instance);

            return NULL;
        }

        instance->n_timestamps_unix_nano = timestamps_count;
    }

    return instance;
}






static
    Opentelemetry__Proto__Resource__V1__Resource *
        initialize_resource(size_t attribute_count) {
    Opentelemetry__Proto__Resource__V1__Resource *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Resource__V1__Resource));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__resource__v1__resource__init(instance);

    if (attribute_count > 0) {
        instance->attributes = initialize_attribute_list(attribute_count);

        if (instance->attributes == NULL) {
            free(instance);

            return NULL;
        }
    }

    instance->n_attributes = attribute_count;

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__Link *
        initialize_link() {
    Opentelemetry__Proto__Profiles__V1development__Link *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Link));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__link__init(instance);

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__Location *
        initialize_location(size_t line_count, size_t attribute_count) {
    Opentelemetry__Proto__Profiles__V1development__Location *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Location));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__location__init(instance);

    if (line_count > 0) {
        instance->lines = calloc(line_count, sizeof(void *));

        if (instance->lines == NULL) {
            destroy_location(instance);

            return NULL;
        }

        instance->n_lines = line_count;
    }

    if (attribute_count > 0) {
        instance->attribute_indices = calloc(attribute_count, sizeof(int32_t));

        if (instance->attribute_indices == NULL) {
            destroy_location(instance);

            return NULL;
        }

        instance->n_attribute_indices = attribute_count;
    }

    return instance;
}

static
    Opentelemetry__Proto__Common__V1__InstrumentationScope *
        initialize_instrumentation_scope(size_t attribute_count) {
    Opentelemetry__Proto__Common__V1__InstrumentationScope *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__InstrumentationScope));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__instrumentation_scope__init(instance);

    if (attribute_count > 0) {
        instance->attributes = initialize_attribute_list(attribute_count);

        if (instance->attributes == NULL) {
            free(instance);

            return NULL;
        }
    }

    instance->n_attributes = attribute_count;

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__Profile *
        initialize_profile(size_t sample_count, size_t attribute_index_count) {
    Opentelemetry__Proto__Profiles__V1development__Profile *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Profile));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__profile__init(instance);

    if (sample_count > 0) {
        instance->samples = calloc(sample_count, sizeof(void *));

        if (instance->samples == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_samples = sample_count;
    }

    if (attribute_index_count > 0) {
        instance->attribute_indices = calloc(attribute_index_count, sizeof(int32_t));

        if (instance->attribute_indices == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_attribute_indices = attribute_index_count;
    }

    return instance;
}


static
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *
        initialize_scope_profiles(size_t profiles_count) {
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__ScopeProfiles));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__scope_profiles__init(instance);

    instance->profiles = calloc(profiles_count, sizeof(void *));

    if (instance->profiles == NULL) {
        free(instance);

        return NULL;
    }

    instance->n_profiles = profiles_count;

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *
        initialize_resource_profiles(size_t scope_profiles_count) {
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__ResourceProfiles));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__resource_profiles__init(instance);

    instance->scope_profiles = calloc(scope_profiles_count, sizeof(void *));

    if (instance->scope_profiles == NULL) {
        free(instance);

        return NULL;
    }

    instance->n_scope_profiles = scope_profiles_count;

    return instance;
}


static
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *
        initialize_export_profiles_service_request(size_t resource_profiles_count) {
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__init(instance);

    instance->resource_profiles = calloc(resource_profiles_count, sizeof(void *));

    if (instance->resource_profiles == NULL) {
        free(instance);

        return NULL;
    }

    instance->n_resource_profiles = resource_profiles_count;

    return instance;
}





static int pack_cprof_resource(
            Opentelemetry__Proto__Resource__V1__Resource **output_instance,
            struct cprof_resource *input_instance)
{
    Opentelemetry__Proto__Resource__V1__Resource *otlp_resource;

    if (input_instance != NULL) {
        otlp_resource = initialize_resource(0);

        if (otlp_resource == NULL) {
            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        otlp_resource->attributes = cfl_kvlist_to_otlp_kvpair_list(input_instance->attributes);

        if (otlp_resource->attributes == NULL) {
            destroy_resource(otlp_resource);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        otlp_resource->n_attributes = cfl_kvlist_count(input_instance->attributes);

        otlp_resource->dropped_attributes_count = \
            input_instance->dropped_attributes_count;

        *output_instance = otlp_resource;
    }

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_instrumentation_scope(
            Opentelemetry__Proto__Common__V1__InstrumentationScope **output_instance,
            struct cprof_instrumentation_scope *input_instance)
{
    Opentelemetry__Proto__Common__V1__InstrumentationScope *otlp_instrumentation_scope;

    if (input_instance != NULL) {
        otlp_instrumentation_scope = initialize_instrumentation_scope(0);

        if (otlp_instrumentation_scope == NULL) {
            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        otlp_instrumentation_scope->attributes = cfl_kvlist_to_otlp_kvpair_list(input_instance->attributes);

        if (otlp_instrumentation_scope->attributes == NULL) {
            destroy_instrumentation_scope(otlp_instrumentation_scope);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        otlp_instrumentation_scope->n_attributes = cfl_kvlist_count(input_instance->attributes);

        if (input_instance->name != NULL) {
            otlp_instrumentation_scope->name = cfl_sds_create(input_instance->name);

            if (otlp_instrumentation_scope->name == NULL) {
                destroy_instrumentation_scope(otlp_instrumentation_scope);

                return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }
        }

        if (input_instance->version != NULL) {
            otlp_instrumentation_scope->version = cfl_sds_create(input_instance->version);

            if (otlp_instrumentation_scope->version == NULL) {
                destroy_instrumentation_scope(otlp_instrumentation_scope);

                return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }
        }

        otlp_instrumentation_scope->dropped_attributes_count = \
            input_instance->dropped_attributes_count;

        *output_instance = otlp_instrumentation_scope;
    }

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_value_type(
            Opentelemetry__Proto__Profiles__V1development__ValueType **output_instance,
            struct cprof_value_type *input_instance,
            struct profile_encoding_state *encoding_state)
{
    Opentelemetry__Proto__Profiles__V1development__ValueType *otlp_value_type;

    otlp_value_type = initialize_value_type();

    if (otlp_value_type == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (encoding_state != NULL && encoding_state->string_map != NULL) {
        if ((size_t)input_instance->type < encoding_state->string_map_count) {
            otlp_value_type->type_strindex = encoding_state->string_map[input_instance->type];
        }
        else {
            otlp_value_type->type_strindex = 0;
        }
        if ((size_t)input_instance->unit < encoding_state->string_map_count) {
            otlp_value_type->unit_strindex = encoding_state->string_map[input_instance->unit];
        }
        else {
            otlp_value_type->unit_strindex = 0;
        }
    }
    else {
        otlp_value_type->type_strindex = 0;
        otlp_value_type->unit_strindex = 0;
    }

    *output_instance = otlp_value_type;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_sample(
            Opentelemetry__Proto__Profiles__V1development__Sample **output_instance,
            struct cprof_sample *input_instance,
            struct profile_encoding_state *encoding_state,
            size_t sample_index)
{
    Opentelemetry__Proto__Profiles__V1development__Sample *otlp_sample;
    size_t                                                 index;

    otlp_sample = initialize_sample(input_instance->value_count,
                                    input_instance->attributes_count,
                                    input_instance->timestamps_count);

    if (otlp_sample == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (encoding_state != NULL && encoding_state->stack_index_by_sample != NULL &&
        sample_index < encoding_state->sample_count) {
        otlp_sample->stack_index = encoding_state->stack_index_by_sample[sample_index];
    }
    else {
        otlp_sample->stack_index = 0;
    }

    for (index = 0 ;
         index < input_instance->value_count ;
         index++) {
        otlp_sample->values[index] = input_instance->values[index];
    }

    for (index = 0 ;
         index < input_instance->attributes_count ;
         index++) {
        otlp_sample->attribute_indices[index] = (int32_t) input_instance->attributes[index];
    }

    if (encoding_state != NULL && encoding_state->link_map != NULL &&
        (size_t)input_instance->link < encoding_state->link_map_count) {
        otlp_sample->link_index = encoding_state->link_map[input_instance->link];
    }
    else {
        otlp_sample->link_index = 0; /* no link or link_table[0] sentinel */
    }

    for (index = 0 ;
         index < input_instance->timestamps_count ;
         index++) {
        otlp_sample->timestamps_unix_nano[index] = input_instance->timestamps_unix_nano[index];
    }

    *output_instance = otlp_sample;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}


static int pack_cprof_value_type(
            Opentelemetry__Proto__Profiles__V1development__ValueType **output_instance,
            struct cprof_value_type *input_instance,
            struct profile_encoding_state *encoding_state);

static int pack_cprof_sample(
            Opentelemetry__Proto__Profiles__V1development__Sample **output_instance,
            struct cprof_sample *input_instance,
            struct profile_encoding_state *encoding_state,
            size_t sample_index);

static int pack_cprof_profile(
            Opentelemetry__Proto__Profiles__V1development__Profile **output_instance,
            struct cprof_profile *input_instance,
            struct profile_encoding_state *encoding_state)
{
    Opentelemetry__Proto__Profiles__V1development__Profile *otlp_profile;
    struct cfl_list                                        *iterator;
    struct cprof_sample                                    *sample;
    struct cprof_value_type                                *sample_type;
    int                                                     result;
    size_t                                                  index;

    otlp_profile = initialize_profile(cfl_list_size(&input_instance->samples), 0);

    if (otlp_profile == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    /* New Profile has single sample_type; use first from list if any */
    if (!cfl_list_is_empty(&input_instance->sample_type)) {
        sample_type = cfl_list_entry_first(&input_instance->sample_type,
                                           struct cprof_value_type, _head);
        result = pack_cprof_value_type(&otlp_profile->sample_type, sample_type, encoding_state);
        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);
            return result;
        }
    }

    index = 0;
    cfl_list_foreach(iterator, &input_instance->samples) {
        sample = cfl_list_entry(iterator, struct cprof_sample, _head);
        result = pack_cprof_sample(&otlp_profile->samples[index], sample, encoding_state, index);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);
            return result;
        }
        index++;
    }

    otlp_profile->time_unix_nano = input_instance->time_nanos;
    otlp_profile->duration_nano = input_instance->duration_nanos;

    result = pack_cprof_value_type(&otlp_profile->period_type, &input_instance->period_type, encoding_state);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        destroy_profile(otlp_profile);
        return result;
    }

    otlp_profile->period = input_instance->period;

    *output_instance = otlp_profile;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_scope_profiles(
            Opentelemetry__Proto__Profiles__V1development__ScopeProfiles **output_instance,
            struct cprof_scope_profiles *input_instance,
            encoder_internal_ctx_t *internal_ctx)
{
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *otlp_scope_profiles;
    struct cfl_list                                              *iterator;
    struct cprof_profile                                         *profile;
    struct profile_encoding_state                                *encoding_state;
    int                                                           result;
    size_t                                                        index;

    otlp_scope_profiles = initialize_scope_profiles(cfl_list_size(&input_instance->profiles));

    if (otlp_scope_profiles == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (input_instance->scope != NULL) {
        result = pack_cprof_instrumentation_scope(&otlp_scope_profiles->scope, input_instance->scope);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            return result;
        }
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->profiles) {
        profile = cfl_list_entry(
                    iterator,
                    struct cprof_profile, _head);

        encoding_state = (internal_ctx->current_profile_index < internal_ctx->encoding_states_count)
            ? &internal_ctx->encoding_states[internal_ctx->current_profile_index++] : NULL;

        result = pack_cprof_profile(
                    &otlp_scope_profiles->profiles[index],
                    profile,
                    encoding_state);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_scope_profiles(otlp_scope_profiles);

            return result;
        }

        index++;
    }

    if (input_instance->schema_url != NULL) {
        otlp_scope_profiles->schema_url = cfl_sds_create(input_instance->schema_url);

        if (otlp_scope_profiles->schema_url == NULL) {
            destroy_scope_profiles(otlp_scope_profiles);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    *output_instance = otlp_scope_profiles;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_resource_profiles(
            Opentelemetry__Proto__Profiles__V1development__ResourceProfiles **output_instance,
            struct cprof_resource_profiles *input_instance,
            encoder_internal_ctx_t *internal_ctx)
{
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *otlp_resource_profiles;
    struct cprof_scope_profiles                                     *scope_profiles;
    struct cfl_list                                                 *iterator;
    int                                                              result;
    size_t                                                           index;

    otlp_resource_profiles = initialize_resource_profiles(cfl_list_size(&input_instance->scope_profiles));

    if (otlp_resource_profiles == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = pack_cprof_resource(&otlp_resource_profiles->resource, input_instance->resource);

    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->scope_profiles) {
        scope_profiles = cfl_list_entry(
                            iterator,
                            struct cprof_scope_profiles, _head);

        result = pack_cprof_scope_profiles(
                    &otlp_resource_profiles->scope_profiles[index],
                    scope_profiles,
                    internal_ctx);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_resource_profiles(otlp_resource_profiles);

            return result;
        }

        index++;
    }

    if (input_instance->schema_url != NULL) {
        otlp_resource_profiles->schema_url = cfl_sds_create(input_instance->schema_url);

        if (otlp_resource_profiles->schema_url == NULL) {
            destroy_resource_profiles(otlp_resource_profiles);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    *output_instance = otlp_resource_profiles;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}


static int pack_cprof_resource_profiles(
            Opentelemetry__Proto__Profiles__V1development__ResourceProfiles **output_instance,
            struct cprof_resource_profiles *input_instance,
            encoder_internal_ctx_t *internal_ctx);

static int pack_cprof_scope_profiles(
            Opentelemetry__Proto__Profiles__V1development__ScopeProfiles **output_instance,
            struct cprof_scope_profiles *input_instance,
            encoder_internal_ctx_t *internal_ctx);

static int pack_cprof_profile(
            Opentelemetry__Proto__Profiles__V1development__Profile **output_instance,
            struct cprof_profile *input_instance,
            struct profile_encoding_state *encoding_state);

static int pack_context_profiles(
            encoder_internal_ctx_t *internal_ctx,
            struct cprof *profile)
{
    size_t                          index;
    int                             result;
    struct cfl_list                *iterator;
    struct cprof_resource_profiles *resource_profiles;

    internal_ctx->pub->export_service_request = \
        initialize_export_profiles_service_request(cfl_list_size(&profile->profiles));

    if (internal_ctx->pub->export_service_request == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &profile->profiles) {
        resource_profiles = cfl_list_entry(
                                iterator,
                                struct cprof_resource_profiles, _head);

        result = pack_cprof_resource_profiles(
                    &internal_ctx->pub->export_service_request->resource_profiles[index],
                    resource_profiles,
                    internal_ctx);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_export_profiles_service_request(internal_ctx->pub->export_service_request);

            return result;
        }

        index++;
    }

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_context(
            struct cprof_opentelemetry_encoding_context *context,
            struct cprof *profile)
{
    encoder_internal_ctx_t                                               internal_ctx;
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary    *dict;
    struct profile_encoding_state                                       *states;
    size_t                                                                state_count;
    int                                                                   result;
    size_t                                                                i;

    memset(context, 0, sizeof(struct cprof_opentelemetry_encoding_context));

    context->inner_context = profile;

    result = build_profiles_dictionary(profile, &dict, &states, &state_count);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    internal_ctx.pub = context;
    internal_ctx.encoding_states = states;
    internal_ctx.encoding_states_count = state_count;
    internal_ctx.current_profile_index = 0;

    result = pack_context_profiles(&internal_ctx, profile);
    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        for (i = 0; i < state_count; i++) {
            free_profile_encoding_state(&states[i]);
        }
        free(states);
        if (dict != NULL) {
            destroy_profiles_dictionary(dict);
        }
        return result;
    }

    if (internal_ctx.pub->export_service_request != NULL && dict != NULL) {
        internal_ctx.pub->export_service_request->dictionary = dict;
    }

    for (i = 0; i < state_count; i++) {
        free_profile_encoding_state(&states[i]);
    }
    free(states);

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static cfl_sds_t render_opentelemetry_context_to_sds(
    struct cprof_opentelemetry_encoding_context *context)
{
    cfl_sds_t result_buffer;
    size_t    result_size;

    result_size = opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__get_packed_size(
                    context->export_service_request);

    result_buffer = cfl_sds_create_size(result_size);

    if(result_buffer != NULL) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__pack(
            context->export_service_request,
            (uint8_t *) result_buffer);

        cfl_sds_set_len(result_buffer, result_size);
    }

    return result_buffer;
}

int cprof_encode_opentelemetry_create(cfl_sds_t *result_buffer,
                                      struct cprof *profile)
{
    int                                         result;
    struct cprof_opentelemetry_encoding_context context;

    *result_buffer = NULL;

    result = pack_context(&context, profile);

    if (result == CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        *result_buffer = render_opentelemetry_context_to_sds(&context);

        if (*result_buffer == NULL) {
            result = CPROF_ENCODE_OPENTELEMETRY_INTERNAL_ENCODER_ERROR;
        }

        destroy_export_profiles_service_request(context.export_service_request);
    }

    return result;
}

void cprof_encode_opentelemetry_destroy(cfl_sds_t instance)
{
    if (instance != NULL) {
        cfl_sds_destroy(instance);
    }
}
