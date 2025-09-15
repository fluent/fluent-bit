#include <cprofiles/cprof_decode_opentelemetry.h>
#include <cfl/cfl_variant.h>

static struct cfl_variant *clone_variant(Opentelemetry__Proto__Common__V1__AnyValue *source);

static int clone_array(struct cfl_array *target,
                       Opentelemetry__Proto__Common__V1__ArrayValue *source);
static int clone_array_entry(struct cfl_array *target,
                             Opentelemetry__Proto__Common__V1__AnyValue *source);
static int clone_kvlist(struct cfl_kvlist *target,
                                Opentelemetry__Proto__Common__V1__KeyValueList *source);
static int clone_kvlist_entry(struct cfl_kvlist *target,
                           Opentelemetry__Proto__Common__V1__KeyValue *source);
static int convert_kvarray_to_kvlist(struct cfl_kvlist *target,
                                     Opentelemetry__Proto__Common__V1__KeyValue **source,
                                     size_t source_length);


static struct cfl_variant *clone_variant(Opentelemetry__Proto__Common__V1__AnyValue *source)
{
    struct cfl_kvlist  *new_child_kvlist;
    struct cfl_array   *new_child_array;
    struct cfl_variant *result_instance = NULL;
    int                 result;

    if (source == NULL) {
        return NULL;
    }
    if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
        result_instance = cfl_variant_create_from_string(source->string_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE) {
        result_instance = cfl_variant_create_from_bool(source->bool_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE) {
        result_instance = cfl_variant_create_from_int64(source->int_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE) {
        result_instance = cfl_variant_create_from_double(source->double_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
        new_child_kvlist = cfl_kvlist_create();
        if (new_child_kvlist == NULL) {
            return NULL;
        }

        result_instance = cfl_variant_create_from_kvlist(new_child_kvlist);

        if (result_instance == NULL) {
            cfl_kvlist_destroy(new_child_kvlist);

            return NULL;
        }

        result = clone_kvlist(new_child_kvlist, source->kvlist_value);
        if (result) {
            cfl_variant_destroy(result_instance);

            return NULL;
        }
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE) {
        new_child_array = cfl_array_create(source->array_value->n_values);

        if (new_child_array == NULL) {
            return NULL;
        }

        result_instance = cfl_variant_create_from_array(new_child_array);
        if (result_instance == NULL) {
            cfl_array_destroy(new_child_array);

            return NULL;
        }

        result = clone_array(new_child_array, source->array_value);
        if (result) {
            cfl_variant_destroy(result_instance);

            return NULL;
        }
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
        result_instance = cfl_variant_create_from_bytes((char *) source->bytes_value.data, source->bytes_value.len,
                                                        CFL_FALSE);
    }

    return result_instance;
}

static int clone_array(struct cfl_array *target,
                       Opentelemetry__Proto__Common__V1__ArrayValue *source)
{
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source->n_values ;
         index++) {
        result = clone_array_entry(target, source->values[index]);
    }

    return result;
}

static int clone_array_entry(struct cfl_array *target,
                             Opentelemetry__Proto__Common__V1__AnyValue *source)
{
    struct cfl_variant *new_child_instance;
    int                 result;

    new_child_instance = clone_variant(source);
    if (new_child_instance == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = cfl_array_append(target, new_child_instance);
    if (result) {
        cfl_variant_destroy(new_child_instance);
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int clone_kvlist(struct cfl_kvlist *target,
                        Opentelemetry__Proto__Common__V1__KeyValueList *source)
{
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source->n_values ;
         index++) {
        result = clone_kvlist_entry(target, source->values[index]);
    }

    return 0;
}

static int convert_kvarray_to_kvlist(struct cfl_kvlist *target,
                                     Opentelemetry__Proto__Common__V1__KeyValue **source,
                                     size_t source_length)
{
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source_length ;
         index++) {
        result = clone_kvlist_entry(target, source[index]);
    }

    return result;
}

static int clone_kvlist_entry(struct cfl_kvlist *target,
                              Opentelemetry__Proto__Common__V1__KeyValue *source)
{
    struct cfl_variant *new_child_instance;
    int                 result;

    new_child_instance = clone_variant(source->value);

    if (new_child_instance == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = cfl_kvlist_insert(target, source->key, new_child_instance);

    if (result) {
        cfl_variant_destroy(new_child_instance);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}
