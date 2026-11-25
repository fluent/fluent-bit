/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_json_tree.h>

#include <string.h>

#include "flb_tests_internal.h"

#ifdef FLB_HAVE_YYJSON
static struct flb_json_tree *tree_read(const char *json)
{
    return flb_json_tree_read(json, strlen(json));
}

static void test_tree_types()
{
    size_t index;
    size_t maximum;
    struct flb_json_tree *tree;
    struct flb_json_node *root;
    struct flb_json_node *key;
    struct flb_json_node *value;
    static const char *names[] = {"n", "b", "u", "s", "r", "t", "a", "o"};

    tree = tree_read("{\"n\":null,\"b\":true,\"u\":18446744073709551615,"
                     "\"s\":-42,\"r\":1.5,\"t\":\"text\",\"a\":[1,2],\"o\":{}}");
    TEST_CHECK(tree != NULL);
    if (tree == NULL) {
        return;
    }

    root = flb_json_tree_root(tree);
    TEST_CHECK(flb_json_node_is_obj(root));
    TEST_CHECK(flb_json_node_obj_size(root) == 8);

    flb_json_node_obj_foreach(root, index, maximum, key, value) {
        TEST_CHECK(flb_json_node_is_str(key));
        TEST_CHECK(flb_json_node_get_len(key) == 1);
        TEST_CHECK(strncmp(flb_json_node_get_str(key), names[index], 1) == 0);

        switch (index) {
        case 0:
            TEST_CHECK(flb_json_node_is_null(value));
            break;
        case 1:
            TEST_CHECK(flb_json_node_is_bool(value) && flb_json_node_get_bool(value));
            break;
        case 2:
            TEST_CHECK(flb_json_node_is_uint(value) && flb_json_node_is_int(value));
            TEST_CHECK(flb_json_node_get_uint(value) == UINT64_MAX);
            break;
        case 3:
            TEST_CHECK(flb_json_node_is_sint(value) && flb_json_node_is_int(value));
            TEST_CHECK(flb_json_node_get_sint(value) == -42);
            break;
        case 4:
            TEST_CHECK(flb_json_node_is_real(value) && !flb_json_node_is_int(value));
            TEST_CHECK(flb_json_node_get_real(value) == 1.5);
            break;
        case 5:
            TEST_CHECK(flb_json_node_is_str(value));
            TEST_CHECK(flb_json_node_get_len(value) == 4);
            TEST_CHECK(strncmp(flb_json_node_get_str(value), "text", 4) == 0);
            break;
        case 6:
            TEST_CHECK(flb_json_node_is_arr(value));
            TEST_CHECK(flb_json_node_arr_size(value) == 2);
            break;
        case 7:
            TEST_CHECK(flb_json_node_is_obj(value));
            TEST_CHECK(flb_json_node_obj_size(value) == 0);
            TEST_CHECK(flb_json_node_first(value) == NULL);
            break;
        }
    }
    TEST_CHECK(index == 8);

    flb_json_tree_destroy(tree);
}

static void test_tree_nested_iteration()
{
    size_t total;
    size_t index;
    size_t maximum;
    size_t inner_index;
    size_t inner_maximum;
    struct flb_json_tree *tree;
    struct flb_json_node *root;
    struct flb_json_node *entry;
    struct flb_json_node *inner;

    /* containers inside arrays must be skipped as a whole */
    tree = tree_read("[[1,[2,3]],{\"k\":[4,{\"x\":5}]},6]");
    TEST_CHECK(tree != NULL);
    if (tree == NULL) {
        return;
    }

    root = flb_json_tree_root(tree);
    TEST_CHECK(flb_json_node_arr_size(root) == 3);

    total = 0;
    flb_json_node_arr_foreach(root, index, maximum, entry) {
        if (index == 0) {
            TEST_CHECK(flb_json_node_is_arr(entry));
            flb_json_node_arr_foreach(entry, inner_index, inner_maximum, inner) {
                total++;
            }
        }
        else if (index == 1) {
            TEST_CHECK(flb_json_node_is_obj(entry));
            inner = flb_json_node_key_value(flb_json_node_first(entry));
            TEST_CHECK(flb_json_node_is_arr(inner));
            TEST_CHECK(flb_json_node_arr_size(inner) == 2);
        }
        else {
            TEST_CHECK(flb_json_node_is_uint(entry));
            TEST_CHECK(flb_json_node_get_uint(entry) == 6);
        }
    }
    TEST_CHECK(index == 3);
    TEST_CHECK(total == 2);

    flb_json_tree_destroy(tree);
}

static void test_tree_invalid_unicode()
{
    size_t index;
    struct flb_json_tree *tree;
    struct flb_json_node *root;
    const char *inputs[] = {
        "\"a\\uD800b\"",
        "\"\\uD800\\u0041\"",
        "\"\\uA_CD\"",
        "\"\\uD800\\uXXXX\""
    };
    const char *expected[] = {
        "a\xef\xbf\xbd" "b",
        "\xef\xbf\xbd",
        "\\uACD",
        "\xef\xbf\xbd" "XXXX"
    };

    /* Preserve the pre-upgrade character handling used by flb_pack_json(). */
    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
        tree = tree_read(inputs[index]);
        TEST_ASSERT(tree != NULL);

        root = flb_json_tree_root(tree);
        TEST_CHECK(flb_json_node_is_str(root));
        TEST_CHECK(flb_json_node_get_len(root) == strlen(expected[index]));
        TEST_CHECK(memcmp(flb_json_node_get_str(root), expected[index],
                          strlen(expected[index])) == 0);

        flb_json_tree_destroy(tree);
    }
}

static void test_tree_rejects()
{
    TEST_CHECK(flb_json_tree_read(NULL, 0) == NULL);
    TEST_CHECK(tree_read("") == NULL);
    TEST_CHECK(tree_read("{\"a\":") == NULL);
    TEST_CHECK(tree_read("{} trailing") == NULL);
    TEST_CHECK(tree_read("{}{}") == NULL);
}
#endif

static void test_tree_null_nodes()
{
    TEST_CHECK(flb_json_tree_root(NULL) == NULL);
    TEST_CHECK(!flb_json_node_is_null(NULL));
    TEST_CHECK(!flb_json_node_is_str(NULL));
    TEST_CHECK(!flb_json_node_is_obj(NULL));
    TEST_CHECK(!flb_json_node_is_arr(NULL));
    TEST_CHECK(flb_json_node_get_str(NULL) == NULL);
    TEST_CHECK(flb_json_node_get_len(NULL) == 0);
    TEST_CHECK(flb_json_node_arr_size(NULL) == 0);
    TEST_CHECK(flb_json_node_obj_size(NULL) == 0);
    TEST_CHECK(flb_json_node_first(NULL) == NULL);
    TEST_CHECK(flb_json_node_next(NULL) == NULL);
    TEST_CHECK(flb_json_node_key_value(NULL) == NULL);
    flb_json_tree_destroy(NULL);
}

#ifndef FLB_HAVE_YYJSON
static void test_tree_unavailable()
{
    /* without a tree backend callers keep their other way to read JSON */
    TEST_CHECK(flb_json_tree_read("{}", 2) == NULL);
}
#endif

TEST_LIST = {
#ifdef FLB_HAVE_YYJSON
    { "tree_types", test_tree_types },
    { "tree_nested_iteration", test_tree_nested_iteration },
    { "tree_invalid_unicode", test_tree_invalid_unicode },
    { "tree_rejects", test_tree_rejects },
#else
    { "tree_unavailable", test_tree_unavailable },
#endif
    { "tree_null_nodes", test_tree_null_nodes },
    { 0 }
};
