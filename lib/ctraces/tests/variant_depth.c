/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <ctraces/ctraces.h>
#include <ctraces/ctr_variant_utils.h>
#include "ctr_tests.h"

static void check_depth(size_t depth, int shape, int expected)
{
    mpack_writer_t writer;
    mpack_reader_t reader;
    struct cfl_kvlist *decoded;
    char *data;
    size_t size;
    size_t index;
    int result;
    int is_map;

    data = NULL;
    size = 0;
    decoded = NULL;
    mpack_writer_init_growable(&writer, &data, &size);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "deep");
    for (index = 0; index < depth; index++) {
        is_map = shape == 0 || (shape == 2 && index % 2 == 0);
        if (is_map) {
            mpack_start_map(&writer, 1);
            mpack_write_cstr(&writer, "k");
        }
        else {
            mpack_start_array(&writer, 1);
        }
    }
    mpack_write_cstr(&writer, "leaf");
    for (index = depth; index > 0; index--) {
        is_map = shape == 0 || (shape == 2 && (index - 1) % 2 == 0);
        if (is_map) {
            mpack_finish_map(&writer);
        }
        else {
            mpack_finish_array(&writer);
        }
    }
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);
    mpack_reader_init_data(&reader, data, size);
    result = unpack_cfl_kvlist(&reader, &decoded);
    TEST_CHECK((result == 0) == expected);
    if (decoded != NULL) {
        cfl_kvlist_destroy(decoded);
    }
    mpack_reader_destroy(&reader);
    free(data);
}

static void test_depth_controls(void)
{
    int shape;

    for (shape = 0; shape < 3; shape++) {
        check_depth(0, shape, 1);
        check_depth(8, shape, 1);
        check_depth(30, shape, 1);
        check_depth(31, shape, 1);
    }
}

static void test_depth_limit(void)
{
    int shape;

    for (shape = 0; shape < 3; shape++) {
        check_depth(32, shape, 0);
        check_depth(400, shape, 0);
    }
}

TEST_LIST = {
    {"depth_controls", test_depth_controls},
    {"depth_limit", test_depth_limit},
    {NULL, NULL}
};
