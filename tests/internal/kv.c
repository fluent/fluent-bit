/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include "flb_tests_internal.h"

static void test_kv_item_set_duplicate()
{
    struct mk_list list;
    struct flb_kv *kv;
    const char *val;

    flb_kv_init(&list);

    kv = flb_kv_item_set(&list, "color", "blue");
    TEST_CHECK(kv != NULL);

    kv = flb_kv_item_set(&list, "color", "green");
    TEST_CHECK(kv != NULL);

    val = flb_kv_get_key_value("color", &list);
    TEST_CHECK(val != NULL);
    if (val) {
        TEST_CHECK(strcmp(val, "green") == 0);
    }

    TEST_CHECK(mk_list_size(&list) == 1);

    flb_kv_release(&list);
}

static void test_kv_get_all_key_values()
{
    struct mk_list list;
    struct flb_kv **pairs;
    int count = -1;

    flb_kv_init(&list);

    pairs = flb_kv_get_all_key_values(&list, &count);
    TEST_CHECK(pairs == NULL);
    TEST_CHECK(count == 0);

    flb_kv_item_set(&list, "host", "localhost");
    flb_kv_item_set(&list, "port", "8080");
    flb_kv_item_set(&list, "path", "/api");

    pairs = flb_kv_get_all_key_values(&list, &count);
    TEST_CHECK(pairs != NULL);
    TEST_CHECK(count == 3);

    if (pairs && count == 3) {
        TEST_CHECK(pairs[0] != NULL);
        TEST_CHECK(strcmp(pairs[0]->key, "host") == 0);
        TEST_CHECK(strcmp(pairs[0]->val, "localhost") == 0);

        TEST_CHECK(pairs[1] != NULL);
        TEST_CHECK(strcmp(pairs[1]->key, "port") == 0);
        TEST_CHECK(strcmp(pairs[1]->val, "8080") == 0);

        TEST_CHECK(pairs[2] != NULL);
        TEST_CHECK(strcmp(pairs[2]->key, "path") == 0);
        TEST_CHECK(strcmp(pairs[2]->val, "/api") == 0);
    }

    flb_kv_release(&list);
    flb_free(pairs);
}

TEST_LIST = {
    {"kv_item_set_duplicate", test_kv_item_set_duplicate},
    {"kv_get_all_key_values", test_kv_get_all_key_values},
    {0}
};
