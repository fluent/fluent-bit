#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_utils.h>

#include "flb_tests_internal.h"

struct test_record {
    msgpack_object *obj;
    msgpack_sbuffer sbuf;
    msgpack_zone zone;
    struct cfl_variant *variant;
    struct cfl_kvlist *kvlist;
    /* Stack objects */
    struct cfl_variant stack_variant;
    struct cfl_object stack_obj;
    struct flb_mp_chunk_record chunk;
};


static struct test_record *create_test_record(const char *key, const char *value);
static struct test_record *create_test_record_numeric(const char *key, double value);
static struct test_record *create_test_record_with_meta(const char *key, const char *value,
                                                      const char *meta_key, const char *meta_value);
static void destroy_test_record(struct test_record *record);

static struct test_record *create_test_record(const char *key, const char *value)
{
    struct test_record *record;
    msgpack_packer pck;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *variant = NULL;
    char *key_copy = NULL;
    char *value_copy = NULL;

    record = flb_calloc(1, sizeof(struct test_record));
    if (!record) {
        return NULL;
    }

    /* Initialize buffers */
    msgpack_sbuffer_init(&record->sbuf);
    msgpack_zone_init(&record->zone, 2048);
    msgpack_packer_init(&pck, &record->sbuf, msgpack_sbuffer_write);

    /* Pack key-value */
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, strlen(key));
    msgpack_pack_str_body(&pck, key, strlen(key));
    msgpack_pack_str(&pck, strlen(value));
    msgpack_pack_str_body(&pck, value, strlen(value));

    record->obj = msgpack_zone_malloc(&record->zone, sizeof(msgpack_object));
    if (!record->obj) {
        goto error;
    }

    msgpack_unpack(record->sbuf.data, record->sbuf.size, NULL,
                  &record->zone, record->obj);

    /* Create kvlist */
    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        goto error;
    }

    /* Make copies of strings */
    key_copy = strdup(key);
    value_copy = strdup(value);
    if (!key_copy || !value_copy) {
        goto error;
    }

    /* Insert strings into kvlist */
    if (cfl_kvlist_insert_string(kvlist, key_copy, value_copy) != 0) {
        goto error;
    }

    /* Free our copies since kvlist has them */
    free(key_copy);
    free(value_copy);
    key_copy = value_copy = NULL;

    /* Create variant */
    variant = cfl_variant_create();
    if (!variant) {
        goto error;
    }

    /* Link structures */
    variant->type = CFL_VARIANT_KVLIST;
    variant->data.as_kvlist = kvlist;
    record->variant = variant;
    record->kvlist = kvlist;

    /* Set up stack objects */
    record->stack_variant.type = CFL_VARIANT_KVLIST;
    record->stack_variant.data.as_kvlist = kvlist;
    record->stack_obj.type = CFL_VARIANT_KVLIST;
    record->stack_obj.variant = &record->stack_variant;

    /* Set up chunk record */
    record->chunk.event.body = record->obj;
    record->chunk.cobj_record = &record->stack_obj;

    return record;

error:
    if (key_copy) free(key_copy);
    if (value_copy) free(value_copy);
    if (variant) cfl_variant_destroy(variant);
    if (kvlist) cfl_kvlist_destroy(kvlist);
    if (record) {
        msgpack_zone_destroy(&record->zone);
        msgpack_sbuffer_destroy(&record->sbuf);
        flb_free(record);
    }
    return NULL;
}
static struct test_record *create_test_record_with_meta(const char *key, const char *value,
                                                      const char *meta_key, const char *meta_value)
{
    struct test_record *record = NULL;
    struct cfl_kvlist *meta_kvlist = NULL;
    struct cfl_variant *meta_variant = NULL;
    struct cfl_object *meta_obj = NULL;
    char *meta_key_copy = NULL;
    char *meta_value_copy = NULL;

    /* Create base record */
    record = create_test_record(key, value);
    if (!record) {
        goto error;
    }

    /* Create metadata kvlist */
    meta_kvlist = cfl_kvlist_create();
    if (!meta_kvlist) {
        goto error;
    }

    /* Make string copies */
    meta_key_copy = strdup(meta_key);
    meta_value_copy = strdup(meta_value);
    if (!meta_key_copy || !meta_value_copy) {
        goto error;
    }

    /* Insert strings */
    if (cfl_kvlist_insert_string(meta_kvlist, meta_key_copy, meta_value_copy) != 0) {
        goto error;
    }

    /* Free our string copies since kvlist makes its own copies */
    free(meta_key_copy);
    free(meta_value_copy);
    meta_key_copy = meta_value_copy = NULL;

    /* Create metadata variant */
    meta_variant = cfl_variant_create();
    if (!meta_variant) {
        goto error;
    }

    /* Create metadata object container */
    meta_obj = flb_calloc(1, sizeof(struct cfl_object));
    if (!meta_obj) {
        goto error;
    }

    /* Setup metadata object */
    meta_variant->type = CFL_VARIANT_KVLIST;
    meta_variant->data.as_kvlist = meta_kvlist;
    meta_obj->type = CFL_VARIANT_KVLIST;
    meta_obj->variant = meta_variant;

    /* Attach metadata to record */
    record->chunk.cobj_metadata = meta_obj;

    return record;

error:
    if (meta_key_copy) {
        free(meta_key_copy);
    }
    if (meta_value_copy) {
        free(meta_value_copy);
    }
    if (meta_variant) {
        cfl_variant_destroy(meta_variant);
    }
    if (meta_obj) {
        flb_free(meta_obj);
    }
    if (meta_kvlist) {
        cfl_kvlist_destroy(meta_kvlist);
    }
    if (record) {
        destroy_test_record(record);
    }
    return NULL;
}

static struct test_record *create_test_record_numeric(const char *key, double value)
{
    struct test_record *record;
    msgpack_packer pck;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *variant = NULL;
    char *key_copy = NULL;

    record = flb_calloc(1, sizeof(struct test_record));
    if (!record) {
        return NULL;
    }

    /* Initialize buffers */
    msgpack_sbuffer_init(&record->sbuf);
    msgpack_zone_init(&record->zone, 2048);
    msgpack_packer_init(&pck, &record->sbuf, msgpack_sbuffer_write);

    /* Pack key-value */
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, strlen(key));
    msgpack_pack_str_body(&pck, key, strlen(key));
    msgpack_pack_double(&pck, value);

    /* Unpack to get the object */
    record->obj = msgpack_zone_malloc(&record->zone, sizeof(msgpack_object));
    if (!record->obj) {
        goto error;
    }

    msgpack_unpack(record->sbuf.data, record->sbuf.size, NULL,
                  &record->zone, record->obj);

    /* Create kvlist */
    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        goto error;
    }

    /* Make copy of key */
    key_copy = strdup(key);
    if (!key_copy) {
        goto error;
    }

    /* Insert into kvlist */
    if (cfl_kvlist_insert_double(kvlist, key_copy, value) != 0) {
        goto error;
    }

    /* Free our copy since kvlist has it */
    free(key_copy);
    key_copy = NULL;

    /* Create variant */
    variant = cfl_variant_create();
    if (!variant) {
        goto error;
    }

    /* Link structures */
    variant->type = CFL_VARIANT_KVLIST;
    variant->data.as_kvlist = kvlist;
    record->variant = variant;
    record->kvlist = kvlist;

    /* Set up stack objects */
    record->stack_variant.type = CFL_VARIANT_KVLIST;
    record->stack_variant.data.as_kvlist = kvlist;
    record->stack_obj.type = CFL_VARIANT_KVLIST;
    record->stack_obj.variant = &record->stack_variant;

    /* Set up chunk record */
    record->chunk.event.body = record->obj;
    record->chunk.cobj_record = &record->stack_obj;

    return record;

error:
    if (key_copy) free(key_copy);
    if (variant) cfl_variant_destroy(variant);
    if (kvlist) cfl_kvlist_destroy(kvlist);
    if (record) {
        msgpack_zone_destroy(&record->zone);
        msgpack_sbuffer_destroy(&record->sbuf);
        flb_free(record);
    }
    return NULL;
}

static void destroy_test_record(struct test_record *record)
{
    struct cfl_kvlist *meta_kvlist = NULL;
    struct cfl_kvlist *main_kvlist = NULL;

    if (!record) {
        return;
    }

    /* Save kvlists before modifying anything */
    if (record->chunk.cobj_metadata && record->chunk.cobj_metadata->variant) {
        meta_kvlist = record->chunk.cobj_metadata->variant->data.as_kvlist;
    }
    main_kvlist = record->kvlist;

    /* Null out all references to prevent variant from trying to clean up */
    if (record->chunk.cobj_metadata && record->chunk.cobj_metadata->variant) {
        record->chunk.cobj_metadata->variant->data.as_kvlist = NULL;
        record->chunk.cobj_metadata->variant->type = CFL_VARIANT_STRING;
    }

    if (record->variant) {
        record->variant->data.as_kvlist = NULL;
        record->variant->type = CFL_VARIANT_STRING;
    }

    record->stack_variant.data.as_kvlist = NULL;
    record->kvlist = NULL;

    /* Clean up variants first */
    if (record->chunk.cobj_metadata) {
        if (record->chunk.cobj_metadata->variant) {
            cfl_variant_destroy(record->chunk.cobj_metadata->variant);
        }
        flb_free(record->chunk.cobj_metadata);
    }

    if (record->variant) {
        cfl_variant_destroy(record->variant);
    }

    /* Now clean up kvlists */
    if (meta_kvlist) {
        cfl_kvlist_destroy(meta_kvlist);
    }
    if (main_kvlist) {
        cfl_kvlist_destroy(main_kvlist);
    }

    /* Clean up msgpack resources */
    msgpack_zone_destroy(&record->zone);
    msgpack_sbuffer_destroy(&record->sbuf);

    flb_free(record);
}

void test_condition_equals()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    /* Test matching equals condition */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ, 
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test non-matching equals condition */
    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_numeric()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;
    double val;

    /* Test greater than */
    record_data = create_test_record_numeric("count", 42.0);
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 40.0;
    TEST_CHECK(flb_condition_add_rule(cond, "$count", FLB_RULE_OP_GT,
                                    &val, 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test less than */
    record_data = create_test_record_numeric("count", 42.0);
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 50.0;
    TEST_CHECK(flb_condition_add_rule(cond, "$count", FLB_RULE_OP_LT,
                                    &val, 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_not_equals()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    /* Test not equals - should match */
    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NEQ, 
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test not equals with matching value - should not match */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NEQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_in()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;
    const char *values[] = {"error", "warn", "fatal"};

    /* Test value in array */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test value not in array */
    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_not_in()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;
    const char *values[] = {"error", "warn", "fatal"};

    /* Test value not in array */
    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NOT_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test value in array */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NOT_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_and()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    /* Test both conditions true */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NEQ,
                                    "info", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test one condition false */
    record_data = create_test_record("level", "warn");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NEQ,
                                    "info", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_or()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    /* Test one condition true */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_OR);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "warn", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test both conditions false */
    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_OR);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "warn", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_empty()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    /* Test empty AND condition */
    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);

    /* Test empty OR condition */
    cond = flb_condition_create(FLB_COND_OP_OR);
    TEST_CHECK(cond != NULL);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_regex()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    /* Test matching regex */
    record_data = create_test_record("path", "/api/v1/users");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$path", FLB_RULE_OP_REGEX,
                                    "^/api/.*$", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test non-matching regex */
    record_data = create_test_record("path", "/other/endpoint");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$path", FLB_RULE_OP_REGEX,
                                    "^/api/.*$", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test empty string */
    record_data = create_test_record("path", "");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$path", FLB_RULE_OP_REGEX,
                                    "^/api/.*$", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_invalid_expressions()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    /* Test NULL condition */
    result = flb_condition_evaluate(NULL, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    /* Test NULL record */
    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, NULL);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);

    /* Test invalid record accessor */
    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$[invalid", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_FALSE);

    flb_condition_destroy(cond);

    /* Test invalid operator */
    cond = flb_condition_create(999);  /* Invalid operator */
    TEST_CHECK(cond != NULL);  /* Should still create but with default op */

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);  /* Default AND behavior */

    flb_condition_destroy(cond);

    /* Test NULL key */
    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, NULL, FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_FALSE);

    flb_condition_destroy(cond);

    /* Test NULL value */
    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    NULL, 0, RECORD_CONTEXT_BODY) == FLB_FALSE);

    flb_condition_destroy(cond);

    /* Test invalid regex pattern */
    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_REGEX,
                                    "[invalid", 0, RECORD_CONTEXT_BODY) == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_metadata()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;

    /* Test metadata match */
    record_data = create_test_record_with_meta("message", "test log",
                                             "streamName", "production");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$streamName", FLB_RULE_OP_EQ,
                                    "production", 0, RECORD_CONTEXT_METADATA) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test metadata no match */
    record_data = create_test_record_with_meta("message", "test log",
                                             "streamName", "staging");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$streamName", FLB_RULE_OP_EQ,
                                    "production", 0, RECORD_CONTEXT_METADATA) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test combination of metadata and body conditions */
    record_data = create_test_record_with_meta("level", "error",
                                             "streamName", "production");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$streamName", FLB_RULE_OP_EQ,
                                    "production", 0, RECORD_CONTEXT_METADATA) == FLB_TRUE);
    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "error", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_missing_values()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;
    const char *values[] = {"error", "warn", "fatal"};

    /* Test IN operator with missing body field */
    record_data = create_test_record("other_field", "some_value");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$non_existent", FLB_RULE_OP_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);  /* Missing field should return false */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test NOT_IN operator with present field not in array */
    record_data = create_test_record("level", "info");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NOT_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);  /* Present value not in array should return true */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test NOT_IN operator with present field in array */
    record_data = create_test_record("level", "error");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_NOT_IN,
                                    (void *)values, 3, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);  /* Present value in array should return false */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_border_cases()
{
    struct test_record *record_data;
    struct flb_condition *cond;
    int result;
    const char *values[] = {"error", "warn", "fatal", ""}; // Removed NULL
    double val;

    /* Test numeric comparison with non-numeric string */
    record_data = create_test_record("count", "not_a_number");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 42.0;
    TEST_CHECK(flb_condition_add_rule(cond, "$count", FLB_RULE_OP_GT,
                                    &val, 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);  /* Non-numeric string should fail comparison */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test empty string in IN operator */
    record_data = create_test_record("level", "");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_IN,
                                    (void *)values, 4, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);  /* Empty string should match empty string in array */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test regex with metacharacters */
    record_data = create_test_record("path", "/api/v1/users[123]");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$path", FLB_RULE_OP_REGEX,
                                    "^/api/v1/users\\[[0-9]+\\]$", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test combination of missing and empty fields with AND */
    record_data = create_test_record("level", "");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    /* Use a non-empty string instead of empty string for comparison */
    TEST_CHECK(flb_condition_add_rule(cond, "$level", FLB_RULE_OP_EQ,
                                    "non-empty", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
    TEST_CHECK(flb_condition_add_rule(cond, "$non_existent", FLB_RULE_OP_EQ,
                                    "non-empty", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);  /* Should fail because both conditions are false */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test empty regex pattern - this should fail at rule creation */
    record_data = create_test_record("path", "");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$path", FLB_RULE_OP_REGEX,
                                    "", 0, RECORD_CONTEXT_BODY) == FLB_FALSE);  /* Should fail to create rule */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test metadata with non-existent field */
    record_data = create_test_record_with_meta("message", "test",
                                             "streamName", "production");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    TEST_CHECK(flb_condition_add_rule(cond, "$non_existent", FLB_RULE_OP_EQ,
                                    "production", 0, RECORD_CONTEXT_METADATA) == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);  /* Should fail because metadata field is missing */

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

void test_condition_numeric_edge_cases()
{
    struct test_record *record_data = NULL;
    struct flb_condition *cond = NULL;
    int result;
    double val;

    /* Test non-numeric string */
    record_data = create_test_record("count", "not_a_number");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 42.0;
    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_GT,
                                  &val, 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test infinity */
    record_data = create_test_record("count", "inf");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 1e308;
    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_GT,
                                 &val, 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test negative infinity */
    record_data = create_test_record("count", "-inf");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = -1e308;
    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_LT,
                                 &val, 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test NaN */
    record_data = create_test_record("count", "NaN");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 0.0;
    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_GT,
                                 &val, 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_FALSE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test very large number */
    record_data = create_test_record("count", "1e308");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 1e307;
    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_GT,
                                 &val, 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test very small number */
    record_data = create_test_record("count", "1e-308");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    val = 1e-307;
    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_LT,
                                 &val, 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test zero */
    record_data = create_test_record("count", "0");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_EQ,
                                 "0", 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);

    /* Test negative zero */
    record_data = create_test_record("count", "-0");
    TEST_CHECK(record_data != NULL);

    cond = flb_condition_create(FLB_COND_OP_AND);
    TEST_CHECK(cond != NULL);

    result = flb_condition_add_rule(cond, "$count", FLB_RULE_OP_EQ,
                                 "-0", 0, RECORD_CONTEXT_BODY);
    TEST_CHECK(result == FLB_TRUE);

    result = flb_condition_evaluate(cond, &record_data->chunk);
    TEST_CHECK(result == FLB_TRUE);

    flb_condition_destroy(cond);
    destroy_test_record(record_data);
}

TEST_LIST = {
    {"equals", test_condition_equals},
    {"not_equals", test_condition_not_equals},
    {"numeric", test_condition_numeric},
    {"numeric_edge_cases", test_condition_numeric_edge_cases},
    {"in", test_condition_in},
    {"not_in", test_condition_not_in},
    {"regex", test_condition_regex},
    {"and", test_condition_and},
    {"or", test_condition_or},
    {"empty", test_condition_empty},
    {"invalid_expressions", test_condition_invalid_expressions},
    {"metadata", test_condition_metadata},
    {"missing_values", test_condition_missing_values},
    {"border_cases", test_condition_border_cases},
    {NULL, NULL}
};