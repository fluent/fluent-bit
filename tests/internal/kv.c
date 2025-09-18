/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_kv.h>
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

TEST_LIST = {
    {"kv_item_set_duplicate", test_kv_item_set_duplicate},
    {0}
};
