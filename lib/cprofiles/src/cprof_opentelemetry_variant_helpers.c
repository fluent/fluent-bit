#include <cprofiles/cprof_decode_opentelemetry.h>
#include <cfl/cfl_variant.h>

static int clone_variant(struct cfl_variant **result_instance,
                         Opentelemetry__Proto__Common__V1__AnyValue *source,
                         char **string_table,
                         size_t string_table_len);

static int clone_array(struct cfl_array *target,
                       Opentelemetry__Proto__Common__V1__ArrayValue *source,
                       char **string_table,
                       size_t string_table_len);
static int clone_array_entry(struct cfl_array *target,
                             Opentelemetry__Proto__Common__V1__AnyValue *source,
                             char **string_table,
                             size_t string_table_len);
static int clone_kvlist(struct cfl_kvlist *target,
                                Opentelemetry__Proto__Common__V1__KeyValueList *source,
                                char **string_table,
                                size_t string_table_len);
static int clone_kvlist_entry(struct cfl_kvlist *target,
                           Opentelemetry__Proto__Common__V1__KeyValue *source,
                           char **string_table,
                           size_t string_table_len);
static int convert_kvarray_to_kvlist(struct cfl_kvlist *target,
                                     Opentelemetry__Proto__Common__V1__KeyValue **source,
                                     size_t source_length,
                                     char **string_table,
                                     size_t string_table_len);

static int convert_keyvalueandunit_array_to_kvlist(struct cfl_kvlist *target,
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit **source,
    size_t source_length,
    char **string_table,
    size_t string_table_len);


static int clone_variant(struct cfl_variant **result_instance,
                         Opentelemetry__Proto__Common__V1__AnyValue *source,
                         char **string_table,
                         size_t string_table_len)
{
    struct cfl_kvlist  *new_child_kvlist;
    struct cfl_array   *new_child_array;
    const char         *resolved_string;
    int                 result;

    *result_instance = NULL;

    if (source == NULL) {
        *result_instance = cfl_variant_create_from_string("");

        return *result_instance != NULL ?
               CPROF_DECODE_OPENTELEMETRY_SUCCESS :
               CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }
    if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
        *result_instance = cfl_variant_create_from_string(source->string_value != NULL ? source->string_value : "");
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX) {
        if (string_table == NULL ||
            source->string_value_strindex < 0 ||
            (size_t) source->string_value_strindex >= string_table_len ||
            string_table[source->string_value_strindex] == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }

        resolved_string = string_table[source->string_value_strindex];
        *result_instance = cfl_variant_create_from_string((char *) resolved_string);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE) {
        *result_instance = cfl_variant_create_from_bool(source->bool_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE) {
        *result_instance = cfl_variant_create_from_int64(source->int_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE) {
        *result_instance = cfl_variant_create_from_double(source->double_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
        if (source->kvlist_value == NULL) {
            *result_instance = cfl_variant_create_from_string("");

            return *result_instance != NULL ?
                   CPROF_DECODE_OPENTELEMETRY_SUCCESS :
                   CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        new_child_kvlist = cfl_kvlist_create();
        if (new_child_kvlist == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        *result_instance = cfl_variant_create_from_kvlist(new_child_kvlist);

        if (*result_instance == NULL) {
            cfl_kvlist_destroy(new_child_kvlist);

            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = clone_kvlist(new_child_kvlist,
                              source->kvlist_value,
                              string_table,
                              string_table_len);
        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            cfl_variant_destroy(*result_instance);
            *result_instance = NULL;

            return result;
        }
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE) {
        if (source->array_value == NULL) {
            *result_instance = cfl_variant_create_from_string("");

            return *result_instance != NULL ?
                   CPROF_DECODE_OPENTELEMETRY_SUCCESS :
                   CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        new_child_array = cfl_array_create(source->array_value->n_values);

        if (new_child_array == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        *result_instance = cfl_variant_create_from_array(new_child_array);
        if (*result_instance == NULL) {
            cfl_array_destroy(new_child_array);

            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = clone_array(new_child_array,
                             source->array_value,
                             string_table,
                             string_table_len);
        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            cfl_variant_destroy(*result_instance);
            *result_instance = NULL;

            return result;
        }
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
        *result_instance = cfl_variant_create_from_bytes((char *) source->bytes_value.data, source->bytes_value.len,
                                                         CFL_FALSE);
    }
    else {
        *result_instance = cfl_variant_create_from_string("");
    }

    return *result_instance != NULL ?
           CPROF_DECODE_OPENTELEMETRY_SUCCESS :
           CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
}

static int clone_array(struct cfl_array *target,
                       Opentelemetry__Proto__Common__V1__ArrayValue *source,
                       char **string_table,
                       size_t string_table_len)
{
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source->n_values ;
         index++) {
        result = clone_array_entry(target,
                                   source->values[index],
                                   string_table,
                                   string_table_len);
    }

    return result;
}

static int clone_array_entry(struct cfl_array *target,
                             Opentelemetry__Proto__Common__V1__AnyValue *source,
                             char **string_table,
                             size_t string_table_len)
{
    struct cfl_variant *new_child_instance;
    int                 result;

    result = clone_variant(&new_child_instance, source, string_table, string_table_len);
    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    result = cfl_array_append(target, new_child_instance);
    if (result) {
        cfl_variant_destroy(new_child_instance);
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int clone_kvlist(struct cfl_kvlist *target,
                        Opentelemetry__Proto__Common__V1__KeyValueList *source,
                        char **string_table,
                        size_t string_table_len)
{
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source->n_values ;
         index++) {
        result = clone_kvlist_entry(target,
                                    source->values[index],
                                    string_table,
                                    string_table_len);
    }

    return result;
}

static int convert_kvarray_to_kvlist(struct cfl_kvlist *target,
                                     Opentelemetry__Proto__Common__V1__KeyValue **source,
                                     size_t source_length,
                                     char **string_table,
                                     size_t string_table_len)
{
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source_length ;
         index++) {
        result = clone_kvlist_entry(target,
                                    source[index],
                                    string_table,
                                    string_table_len);
    }

    return result;
}

static int clone_kvlist_entry(struct cfl_kvlist *target,
                              Opentelemetry__Proto__Common__V1__KeyValue *source,
                              char **string_table,
                              size_t string_table_len)
{
    struct cfl_variant *new_child_instance;
    int                 result;
    char               *key;
    const char         *resolved_key;

    if (source == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
    }

    if (source->key != NULL && source->key[0] != '\0') {
        resolved_key = source->key;
    }
    else if (string_table != NULL &&
             source->key_strindex >= 0 &&
             (size_t) source->key_strindex < string_table_len &&
             string_table[source->key_strindex] != NULL) {
        resolved_key = string_table[source->key_strindex];
    }
    else if (source->key != NULL) {
        resolved_key = source->key;
    }
    else {
        return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    key = (char *) resolved_key;

    result = clone_variant(&new_child_instance, source->value, string_table, string_table_len);
    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    result = cfl_kvlist_insert(target, key, new_child_instance);

    if (result) {
        cfl_variant_destroy(new_child_instance);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int convert_keyvalueandunit_array_to_kvlist(struct cfl_kvlist *target,
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit **source,
    size_t source_length,
    char **string_table,
    size_t string_table_len)
{
    size_t              index;
    int                 result;
    const char         *key;
    struct cfl_variant *val;
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit *entry;

    for (index = 0; index < source_length; index++) {
        entry = source[index];

        key = "";
        if (entry == NULL) {
            key = "";
        }
        else if (string_table != NULL && entry->key_strindex >= 0 &&
                 (size_t)entry->key_strindex < string_table_len &&
                 string_table[entry->key_strindex] != NULL) {
            key = string_table[entry->key_strindex];
        }
        else {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }

        /*
         * Preserve positional alignment with OTLP attribute table indexes.
         * Even null/sentinel source entries get a placeholder null value,
         * so downstream index-based resolution remains stable.
         */
        if (entry == NULL || entry->value == NULL ||
            entry->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET) {
            val = cfl_variant_create_from_string("");
            if (val == NULL) {
                return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }
        }
        else {
            result = clone_variant(&val, entry->value, string_table, string_table_len);
            if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                return result;
            }
        }

        if (cfl_kvlist_insert(target, (char *)key, val) != 0) {
            cfl_variant_destroy(val);
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}
