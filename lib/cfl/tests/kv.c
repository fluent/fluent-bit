/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#include <cfl/cfl.h>

#include "cfl_tests_internal.h"


static void regular_operation()
{
    struct cfl_list *entry_iterator;
    size_t           entry_index;
    struct cfl_list  entry_list;
    struct cfl_kv   *entry;

    cfl_kv_init(&entry_list);

    entry = cfl_kv_item_create(&entry_list, "first entry", "dummy value");
    TEST_CHECK(entry != NULL);

    entry = cfl_kv_item_create(&entry_list, "second entry", NULL);
    TEST_CHECK(entry != NULL);

    entry = cfl_kv_item_create(&entry_list, NULL, NULL);
    TEST_CHECK(entry == NULL);

    entry = cfl_kv_item_create_len(&entry_list, "third entry", 0, "dummy value", 12);
    TEST_CHECK(entry != NULL);

    entry = cfl_kv_item_create_len(&entry_list, "fourth entry", 13, "dummy value", 0);
    TEST_CHECK(entry != NULL);

    entry_index = 0;

    cfl_list_foreach(entry_iterator, &entry_list) {
        entry = cfl_list_entry(entry_iterator, struct cfl_kv, _head);

        switch (entry_index) {
            case 0:
                TEST_CHECK(strcmp(entry->key, "first entry") == 0);
                TEST_CHECK(strcmp(entry->val, "dummy value") == 0);
                break;
            case 1:
                TEST_CHECK(strcmp(entry->key, "second entry") == 0);
                TEST_CHECK(entry->val == NULL);
                break;
            case 2:
                TEST_CHECK(strlen(entry->key) == 0);
                TEST_CHECK(strcmp(entry->val, "dummy value") == 0);
                break;
            case 3:
                TEST_CHECK(strcmp(entry->key, "fourth entry") == 0);
                TEST_CHECK(entry->val == NULL);
                break;
        }

        entry_index++;
    }

    cfl_kv_release(&entry_list);
}

TEST_LIST = {
    {"regular_operation",  regular_operation},
    { 0 }
};
