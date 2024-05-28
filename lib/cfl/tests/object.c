/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022-2024 The CFL Authors
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

static void test_basics()
{
    int ret;
    struct cfl_object *object;
    struct cfl_kvlist *list;
    struct cfl_array *array;

    object = cfl_object_create();
    TEST_CHECK(object != NULL);

    /*
     * Inserts
     */
    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    ret = cfl_object_set(object, CFL_OBJECT_KVLIST, list);
    TEST_CHECK(ret == 0);

    array = cfl_array_create(2);
    TEST_CHECK(array != NULL);

    ret = cfl_kvlist_insert_array(list, "key1", array);
    TEST_CHECK(ret == 0);

    /*
     * Destroy
     */
    cfl_object_destroy(object);
}

TEST_LIST = {
    { "test_basics", test_basics },
    { 0 }
};
