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
        if (instance->location_index != NULL) {
            free(instance->location_index);
        }

        if (instance->value != NULL) {
            free(instance->value);
        }

        if (instance->attributes != NULL) {
            free(instance->attributes);
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
        if (instance->attributes != NULL) {
            free(instance->attributes);
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
        if (instance->line != NULL) {
            for (index = 0 ; index < instance->n_line ; index++) {
                destroy_line(instance->line[index]);
            }

            free(instance->line);
        }

        if (instance->attributes != NULL) {
            free(instance->attributes);
        }

        free(instance);
    }
}

static void destroy_attribute_unit(
        Opentelemetry__Proto__Profiles__V1development__AttributeUnit *
            instance)
{
    if (instance != NULL) {
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
            for (index = 0 ; index < instance->n_sample_type ; index++) {
                destroy_value_type(instance->sample_type[index]);
            }

            free(instance->sample_type);
        }

        if (instance->sample != NULL) {
            for (index = 0 ; index < instance->n_sample ; index++) {
                destroy_sample(instance->sample[index]);
            }

            free(instance->sample);
        }

        if (instance->mapping != NULL) {
            for (index = 0 ; index < instance->n_mapping ; index++) {
                destroy_mapping(instance->mapping[index]);
            }

            free(instance->mapping);
        }

        if (instance->location != NULL) {
            for (index = 0 ; index < instance->n_location ; index++) {
                destroy_location(instance->location[index]);
            }

            free(instance->location);
        }

        if (instance->location_indices != NULL) {
            free(instance->location_indices);
        }

        if (instance->function != NULL) {
            for (index = 0 ; index < instance->n_function ; index++) {
                destroy_function(instance->function[index]);
            }

            free(instance->function);
        }

        if (instance->attribute_table != NULL) {
            destroy_attribute_list(instance->attribute_table);
        }

        for (index = 0 ; index < instance->n_attribute_units ; index++) {
            destroy_attribute_unit(instance->attribute_units[index]);
        }

        if (instance->link_table != NULL) {
            for (index = 0 ; index < instance->n_link_table ; index++) {
                destroy_link(instance->link_table[index]);
            }

            free(instance->link_table);
        }

        if (instance->string_table != NULL) {
            for (index = 0 ; index < instance->n_string_table ; index++) {
                if (is_string_releaseable(instance->string_table[index])) {
                    cfl_sds_destroy(instance->string_table[index]);
                }
            }

            free(instance->string_table);
        }

        if (instance->period_type != NULL) {
            destroy_value_type(instance->period_type);
        }

        if (instance->comment != NULL) {
            free(instance->comment);
        }

        free(instance);
    }
}

static void destroy_profile_container(
        Opentelemetry__Proto__Profiles__V1development__ProfileContainer *
            instance)
{
    if (instance != NULL) {
        if (instance->profile_id.data != NULL) {
            if (is_string_releaseable((cfl_sds_t) instance->profile_id.data)) {
                cfl_sds_destroy((cfl_sds_t) instance->profile_id.data);
            }
        }

        destroy_attribute_list(instance->attributes);

        if (instance->original_payload_format != NULL) {
            if (is_string_releaseable(instance->original_payload_format)) {
                cfl_sds_destroy(instance->original_payload_format);
            }
        }

        if (instance->original_payload.data != NULL) {
            if (is_string_releaseable((cfl_sds_t) instance->original_payload.data)) {
                cfl_sds_destroy((cfl_sds_t) instance->original_payload.data);
            }
        }

        destroy_profile(instance->profile);

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
                destroy_profile_container(instance->profiles[index]);
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

        free(instance);
    }
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
            size_t location_index_count,
            size_t value_count,
            size_t attributes_count,
            size_t timestamps_count) {
    Opentelemetry__Proto__Profiles__V1development__Sample *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Sample));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__sample__init(instance);

    if (location_index_count > 0) {
        instance->location_index = calloc(location_index_count, sizeof(uint64_t));

        if (instance->location_index == NULL) {
            destroy_sample(instance);

            return NULL;
        }

        instance->n_location_index = location_index_count;
    }

    if (value_count > 0) {
        instance->value = calloc(value_count, sizeof(int64_t));

        if (instance->value == NULL) {
            destroy_sample(instance);

            return NULL;
        }

        instance->n_value = value_count;
    }

    if (attributes_count > 0) {
        instance->attributes = calloc(attributes_count, sizeof(uint64_t));

        if (instance->attributes == NULL) {
            destroy_sample(instance);

            return NULL;
        }

        instance->n_attributes = attributes_count;
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
    Opentelemetry__Proto__Profiles__V1development__AttributeUnit *
        initialize_attribute_unit() {
    Opentelemetry__Proto__Profiles__V1development__AttributeUnit *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__AttributeUnit));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__attribute_unit__init(instance);

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__Line *
        initialize_line() {
    Opentelemetry__Proto__Profiles__V1development__Line *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Line));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__line__init(instance);

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
        instance->line = calloc(line_count, sizeof(void *));

        if (instance->line == NULL) {
            destroy_location(instance);

            return NULL;
        }

        instance->n_line = line_count;
    }

    if (attribute_count > 0) {
        instance->attributes = calloc(attribute_count, sizeof(uint64_t));

        if (instance->attributes == NULL) {
            destroy_location(instance);

            return NULL;
        }

        instance->n_attributes = attribute_count;
    }

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__Function *
        initialize_function() {
    Opentelemetry__Proto__Profiles__V1development__Function *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Function));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__function__init(instance);

    return instance;
}

static
    Opentelemetry__Proto__Profiles__V1development__Mapping *
        initialize_mapping(size_t attribute_count) {
    Opentelemetry__Proto__Profiles__V1development__Mapping *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Mapping));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__mapping__init(instance);

    if (attribute_count > 0) {
        instance->attributes = calloc(attribute_count, sizeof(uint64_t));

        if (instance->attributes == NULL) {
            destroy_mapping(instance);

            return NULL;
        }

        instance->n_attributes = attribute_count;
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
        initialize_profile(
            size_t sample_type_count,
            size_t sample_count,
            size_t mapping_count,
            size_t location_count,
            size_t location_index_count,
            size_t function_count,
            size_t attribute_count,
            size_t attribute_unit_count,
            size_t link_count,
            size_t string_count,
            size_t comment_count) {
    Opentelemetry__Proto__Profiles__V1development__Profile *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__Profile));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__profile__init(instance);

    if (sample_type_count > 0) {
        instance->sample_type = calloc(sample_type_count, sizeof(void *));

        if (instance->sample_type == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_sample_type = sample_type_count;
    }

    if (sample_count > 0) {
        instance->sample = calloc(sample_count, sizeof(void *));

        if (instance->sample == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_sample = sample_count;
    }

    if (mapping_count > 0) {
        instance->mapping = calloc(mapping_count, sizeof(void *));

        if (instance->mapping == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_mapping = mapping_count;
    }

    if (location_count > 0) {
        instance->location = calloc(location_count, sizeof(void *));

        if (instance->location == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_location = location_count;
    }

    if (location_index_count > 0) {
        instance->location_indices = calloc(location_index_count, sizeof(uint64_t));

        if (instance->location_indices == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_location_indices = location_index_count;
    }

    if (function_count > 0) {
        instance->function = calloc(function_count, sizeof(void *));

        if (instance->function == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_function = function_count;
    }

    if (attribute_count > 0) {
        instance->attribute_table = calloc(attribute_count, sizeof(void *));

        if (instance->attribute_table == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_attribute_table = attribute_count;
    }

    if (attribute_unit_count > 0) {
        instance->attribute_units = calloc(attribute_unit_count, sizeof(void *));

        if (instance->attribute_units == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_attribute_units = attribute_unit_count;
    }

    if (link_count > 0) {
        instance->link_table = calloc(link_count, sizeof(void *));

        if (instance->link_table == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_link_table = link_count;
    }

    if (string_count > 0) {
        instance->string_table = calloc(string_count, sizeof(void *));

        if (instance->string_table == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_string_table = string_count;
    }

    if (comment_count > 0) {
        instance->comment = calloc(comment_count, sizeof(void *));

        if (instance->comment == NULL) {
            destroy_profile(instance);

            return NULL;
        }

        instance->n_comment = comment_count;
    }

    return instance;
}


static
    Opentelemetry__Proto__Profiles__V1development__ProfileContainer *
        initialize_profile_container(size_t attribute_count) {
    Opentelemetry__Proto__Profiles__V1development__ProfileContainer *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Profiles__V1development__ProfileContainer));

    if (instance == NULL) {
        return NULL;
    }

    opentelemetry__proto__profiles__v1development__profile_container__init(instance);

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
            struct cprof_value_type *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__ValueType *otlp_value_type;

    otlp_value_type = initialize_value_type();

    if (otlp_value_type == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_value_type->type = input_instance->type;
    otlp_value_type->unit = input_instance->unit;
    otlp_value_type->aggregation_temporality = input_instance->aggregation_temporality;

    *output_instance = otlp_value_type;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_sample(
            Opentelemetry__Proto__Profiles__V1development__Sample **output_instance,
            struct cprof_sample *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Sample *otlp_sample;
    size_t                                                 index;

    otlp_sample = initialize_sample(input_instance->location_index_count,
                                    input_instance->value_count,
                                    input_instance->attributes_count,
                                    input_instance->timestamps_count);

    if (otlp_sample == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    for (index = 0 ;
         index < input_instance->location_index_count ;
         index++) {
        otlp_sample->location_index[index] = input_instance->location_index[index];
    }

    otlp_sample->locations_start_index = input_instance->locations_start_index;
    otlp_sample->locations_length = input_instance->locations_length;

    for (index = 0 ;
         index < input_instance->value_count ;
         index++) {
        otlp_sample->value[index] = input_instance->values[index];
    }

    for (index = 0 ;
         index < input_instance->attributes_count ;
         index++) {
        otlp_sample->attributes[index] = input_instance->attributes[index];
    }

    otlp_sample->link = input_instance->link;

    for (index = 0 ;
         index < input_instance->timestamps_count ;
         index++) {
        otlp_sample->timestamps_unix_nano[index] = input_instance->timestamps_unix_nano[index];
    }

    *output_instance = otlp_sample;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}


static int pack_cprof_mapping(
            Opentelemetry__Proto__Profiles__V1development__Mapping **output_instance,
            struct cprof_mapping *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Mapping *otlp_mapping;
    size_t                                                  index;

    otlp_mapping = initialize_mapping(input_instance->attributes_count);

    if (otlp_mapping == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_mapping->id = input_instance->id;
    otlp_mapping->memory_start = input_instance->memory_start;
    otlp_mapping->memory_limit = input_instance->memory_limit;
    otlp_mapping->file_offset = input_instance->file_offset;
    otlp_mapping->filename = input_instance->filename;

    for (index = 0 ;
         index < input_instance->attributes_count ;
         index++) {
        otlp_mapping->attributes[index] = input_instance->attributes[index];
    }

    otlp_mapping->has_functions = input_instance->has_functions;
    otlp_mapping->has_filenames = input_instance->has_filenames;
    otlp_mapping->has_line_numbers = input_instance->has_line_numbers;
    otlp_mapping->has_inline_frames = input_instance->has_inline_frames;

    *output_instance = otlp_mapping;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}



static int pack_cprof_line(
            Opentelemetry__Proto__Profiles__V1development__Line **output_instance,
            struct cprof_line *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Line *otlp_line;

    otlp_line = initialize_line();

    if (otlp_line == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_line->function_index = input_instance->function_index;
    otlp_line->line = input_instance->line;
    otlp_line->column = input_instance->column;

    *output_instance = otlp_line;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_location(
            Opentelemetry__Proto__Profiles__V1development__Location **output_instance,
            struct cprof_location *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Location *otlp_location;
    struct cfl_list                                        *iterator;
    int                                                     result;
    struct cprof_line                                      *line;
    size_t                                                  index;

    otlp_location = initialize_location(cfl_list_size(&input_instance->lines),
                                        input_instance->attributes_count);

    if (otlp_location == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_location->id = input_instance->id;
    otlp_location->mapping_index = input_instance->mapping_index;
    otlp_location->address = input_instance->address;


    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->lines) {
        line = cfl_list_entry(
                iterator,
                struct cprof_line, _head);

        result = pack_cprof_line(
                    &otlp_location->line[index],
                    line);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_location(otlp_location);

            return result;
        }

        index++;
    }

    otlp_location->is_folded = input_instance->is_folded;

    for (index = 0 ;
         index < input_instance->attributes_count ;
         index++) {
        otlp_location->attributes[index] = input_instance->attributes[index];
    }

    *output_instance = otlp_location;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_function(
            Opentelemetry__Proto__Profiles__V1development__Function **output_instance,
            struct cprof_function *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Function *otlp_function;

    otlp_function = initialize_function();

    if (otlp_function == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_function->id = input_instance->id;
    otlp_function->name = input_instance->name;
    otlp_function->system_name = input_instance->system_name;
    otlp_function->filename = input_instance->filename;
    otlp_function->start_line = input_instance->start_line;

    *output_instance = otlp_function;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_attribute_unit(
            Opentelemetry__Proto__Profiles__V1development__AttributeUnit **output_instance,
            struct cprof_attribute_unit *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__AttributeUnit *otlp_attribute_unit;

    otlp_attribute_unit = initialize_attribute_unit();

    if (otlp_attribute_unit == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_attribute_unit->attribute_key = input_instance->attribute_key;
    otlp_attribute_unit->unit = input_instance->unit;

    *output_instance = otlp_attribute_unit;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_link(
            Opentelemetry__Proto__Profiles__V1development__Link **output_instance,
            struct cprof_link *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Link *otlp_link;

    otlp_link = initialize_link();

    if (otlp_link == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_link->trace_id.data = \
        (uint8_t *) cfl_sds_create_len((const char *) input_instance->trace_id,
                                       sizeof(input_instance->trace_id));

    if (otlp_link->trace_id.data == NULL) {
        destroy_link(otlp_link);

        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_link->trace_id.len = sizeof(input_instance->trace_id);


    otlp_link->span_id.data = \
        (uint8_t *) cfl_sds_create_len((const char *) input_instance->span_id,
                                       sizeof(input_instance->span_id));

    if (otlp_link->span_id.data == NULL) {
        destroy_link(otlp_link);

        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_link->span_id.len = sizeof(input_instance->span_id);


    *output_instance = otlp_link;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_profile(
            Opentelemetry__Proto__Profiles__V1development__Profile **output_instance,
            struct cprof_profile *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__Profile *otlp_profile;
    struct cfl_list                                        *iterator;
    struct cprof_sample                                    *sample;
    struct cprof_link                                      *link;
    struct cprof_mapping                                   *mapping;
    struct cprof_location                                  *location;
    struct cprof_function                                  *function;
    struct cprof_value_type                                *sample_type;
    struct cprof_attribute_unit                            *attribute_unit;
    int                                                     result;
    size_t                                                  index;

    otlp_profile = initialize_profile(cfl_list_size(&input_instance->sample_type),
                                      cfl_list_size(&input_instance->samples),
                                      cfl_list_size(&input_instance->mappings),
                                      cfl_list_size(&input_instance->locations),
                                      input_instance->location_indices_count,
                                      cfl_list_size(&input_instance->functions),
                                      0,
                                      cfl_list_size(&input_instance->attribute_units),
                                      cfl_list_size(&input_instance->link_table),
                                      input_instance->string_table_count,
                                      input_instance->comments_count);

    if (otlp_profile == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->sample_type) {
        sample_type = cfl_list_entry(
                        iterator,
                        struct cprof_value_type, _head);

        result = pack_cprof_value_type(
                    &otlp_profile->sample_type[index],
                    sample_type);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->samples) {
        sample = cfl_list_entry(
                        iterator,
                        struct cprof_sample, _head);

        result = pack_cprof_sample(
                    &otlp_profile->sample[index],
                    sample);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->mappings) {
        mapping = cfl_list_entry(
                        iterator,
                        struct cprof_mapping, _head);

        result = pack_cprof_mapping(
                    &otlp_profile->mapping[index],
                    mapping);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->locations) {
        location = cfl_list_entry(
                        iterator,
                        struct cprof_location, _head);

        result = pack_cprof_location(
                    &otlp_profile->location[index],
                    location);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    for (index = 0 ;
         index < input_instance->location_indices_count ;
         index++) {
        otlp_profile->location_indices[index] = input_instance->location_indices[index];
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->functions) {
        function = cfl_list_entry(
                        iterator,
                        struct cprof_function, _head);

        result = pack_cprof_function(
                    &otlp_profile->function[index],
                    function);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    if (input_instance->attribute_table != NULL) {
        otlp_profile->attribute_table = cfl_kvlist_to_otlp_kvpair_list(input_instance->attribute_table);

        if (otlp_profile->attribute_table == NULL) {
            destroy_profile(otlp_profile);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        otlp_profile->n_attribute_table = cfl_kvlist_count(input_instance->attribute_table);
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->attribute_units) {
        attribute_unit = cfl_list_entry(
                            iterator,
                            struct cprof_attribute_unit, _head);

        result = pack_cprof_attribute_unit(
                    &otlp_profile->attribute_units[index],
                    attribute_unit);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &input_instance->link_table) {
        link = cfl_list_entry(
                iterator,
                struct cprof_link, _head);

        result = pack_cprof_link(
                    &otlp_profile->link_table[index],
                    link);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_profile(otlp_profile);

            return result;
        }

        index++;
    }

    for (index = 0 ;
         index < input_instance->string_table_count ;
         index++) {
        otlp_profile->string_table[index] = cfl_sds_create(input_instance->string_table[index]);

        if (otlp_profile->string_table[index] == NULL) {
            destroy_profile(otlp_profile);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    otlp_profile->drop_frames = input_instance->drop_frames;
    otlp_profile->keep_frames = input_instance->keep_frames;
    otlp_profile->time_nanos = input_instance->time_nanos;
    otlp_profile->duration_nanos = input_instance->duration_nanos;

    result = pack_cprof_value_type(
                &otlp_profile->period_type,
                &input_instance->period_type);

    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        destroy_profile(otlp_profile);

        return result;
    }

    otlp_profile->period = input_instance->period;

    for (index = 0 ;
         index < input_instance->comments_count ;
         index++) {
        otlp_profile->comment[index] = input_instance->comments[index];
    }

    otlp_profile->default_sample_type = input_instance->default_sample_type;

    *output_instance =  otlp_profile;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int pack_cprof_profile_container(
            Opentelemetry__Proto__Profiles__V1development__ProfileContainer **output_instance,
            struct cprof_profile *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__ProfileContainer *otlp_profile_container;
    int                                                              result;

    otlp_profile_container = initialize_profile_container(0);

    if (otlp_profile_container == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_profile_container->profile_id.data = \
        (uint8_t *) cfl_sds_create_len((const char *) input_instance->profile_id,
                                       sizeof(input_instance->profile_id));

    if (otlp_profile_container->profile_id.data == NULL) {
        destroy_profile_container(otlp_profile_container);

        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_profile_container->profile_id.len = sizeof(input_instance->profile_id);

    otlp_profile_container->start_time_unix_nano = (uint64_t) input_instance->start_time_unix_nano;
    otlp_profile_container->end_time_unix_nano = (uint64_t) input_instance->end_time_unix_nano;

    otlp_profile_container->attributes = cfl_kvlist_to_otlp_kvpair_list(input_instance->attributes);

    if (otlp_profile_container->attributes == NULL) {
        destroy_profile_container(otlp_profile_container);

        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    otlp_profile_container->n_attributes = cfl_kvlist_count(input_instance->attributes);

    otlp_profile_container->dropped_attributes_count = input_instance->dropped_attributes_count;

    if (input_instance->original_payload_format != NULL) {
        otlp_profile_container->original_payload_format = \
            cfl_sds_create(input_instance->original_payload_format);

        if (otlp_profile_container->original_payload_format == NULL) {
            destroy_profile_container(otlp_profile_container);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    if (input_instance->original_payload != NULL) {
        otlp_profile_container->original_payload.data = \
            (uint8_t *) cfl_sds_create_len(input_instance->original_payload,
                                           cfl_sds_len(input_instance->original_payload));

        if (otlp_profile_container->original_payload.data == NULL) {
            destroy_profile_container(otlp_profile_container);

            return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        otlp_profile_container->original_payload.len = cfl_sds_len(input_instance->original_payload);
    }

    result = pack_cprof_profile(&otlp_profile_container->profile, input_instance);

    if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
        destroy_profile_container(otlp_profile_container);

        return result;
    }

    *output_instance = otlp_profile_container;

    return CPROF_ENCODE_OPENTELEMETRY_SUCCESS;
}


static int pack_cprof_scope_profiles(
            Opentelemetry__Proto__Profiles__V1development__ScopeProfiles **output_instance,
            struct cprof_scope_profiles *input_instance)
{
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *otlp_scope_profiles;
    struct cfl_list                                              *iterator;
    struct cprof_profile                                         *profile;
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

        result = pack_cprof_profile_container(
                    &otlp_scope_profiles->profiles[index],
                    profile);

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
            struct cprof_resource_profiles *input_instance)
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
                    scope_profiles);

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


static int pack_context_profiles(
            struct cprof_opentelemetry_encoding_context *context,
            struct cprof *profile)
{
    size_t                          index;
    int                             result;
    struct cfl_list                *iterator;
    struct cprof_resource_profiles *resource_profiles;

    context->export_service_request = \
        initialize_export_profiles_service_request(cfl_list_size(&profile->profiles));

    if (context->export_service_request == NULL) {
        return CPROF_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    index = 0;
    cfl_list_foreach(iterator,
                     &profile->profiles) {
        resource_profiles = cfl_list_entry(
                                iterator,
                                struct cprof_resource_profiles, _head);

        result = pack_cprof_resource_profiles(
                    &context->export_service_request->resource_profiles[index],
                    resource_profiles);

        if (result != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_export_profiles_service_request(context->export_service_request);

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
    memset(context, 0, sizeof(struct cprof_opentelemetry_encoding_context));

    context->inner_context = profile;

    return pack_context_profiles(context, profile);
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
