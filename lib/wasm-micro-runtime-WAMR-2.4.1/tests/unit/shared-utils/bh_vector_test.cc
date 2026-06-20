/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"
#include "bh_platform.h"

#include <future>

class bh_vector_test_suite : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp() {}

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

  public:
    WAMRRuntimeRAII<512 * 1024> runtime;
};

static inline void *
malloc_internal(uint64 size);

TEST_F(bh_vector_test_suite, bh_vector_init)
{
    Vector *vector_ptr = nullptr;

    // Normally. use_lock is true.
    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    EXPECT_EQ(true, bh_vector_init(vector_ptr, 6, sizeof(Vector *), true));
    // use_lock is false.
    EXPECT_EQ(true, bh_vector_init(vector_ptr, 6, sizeof(Vector *), false));
    // init_length == 0.
    EXPECT_EQ(true, bh_vector_init(vector_ptr, 0, sizeof(Vector *), false));
    // size_elem > UINT32_MAX.
    EXPECT_EQ(true, bh_vector_init(vector_ptr, 6, UINT32_MAX + 1, false));
    // init_length > UINT32_MAX.
    EXPECT_EQ(true, bh_vector_init(vector_ptr, UINT32_MAX + 1, sizeof(Vector *),
                                   false));

    // Illegal parameters.
    EXPECT_EQ(false, bh_vector_init(nullptr, 6, sizeof(Vector *), true));
}

TEST_F(bh_vector_test_suite, bh_vector_set)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);
    bh_vector_append(vector_ptr, "test");

    // Normally. use_lock is true.
    EXPECT_EQ(true, bh_vector_set(vector_ptr, 0, elem_buf));

    // Illegal parameters: nullptr.
    EXPECT_EQ(false, bh_vector_set(nullptr, 0, nullptr));
    EXPECT_EQ(false, bh_vector_set(vector_ptr, 0, nullptr));
    // Illegal parameters: index >= vector->num_elems.
    EXPECT_EQ(false, bh_vector_set(vector_ptr, 1, elem_buf));

    // Normally. use_lock is false.
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), false);
    bh_vector_append(vector_ptr, "test");
    EXPECT_EQ(true, bh_vector_set(vector_ptr, 0, elem_buf));
}

TEST_F(bh_vector_test_suite, bh_vector_get)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";
    char get_elem[12] = { 0 };

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);
    bh_vector_append(vector_ptr, elem_buf);

    // Normally. use_lock is true.
    EXPECT_EQ(true, bh_vector_get(vector_ptr, 0, get_elem));
    EXPECT_EQ(0, strncmp(elem_buf, get_elem, 11));

    // Illegal parameters: nullptr.
    EXPECT_EQ(false, bh_vector_get(nullptr, 0, nullptr));
    EXPECT_EQ(false, bh_vector_get(vector_ptr, 0, nullptr));
    // Illegal parameters: index >= vector->num_elems.
    EXPECT_EQ(false, bh_vector_get(vector_ptr, 1, get_elem));

    // Normally. use_lock is false.
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), false);
    bh_vector_append(vector_ptr, elem_buf);
    EXPECT_EQ(true, bh_vector_get(vector_ptr, 0, get_elem));
    EXPECT_EQ(0, strncmp(elem_buf, get_elem, 11));
}

TEST_F(bh_vector_test_suite, bh_vector_insert)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";
    char get_elem[12] = { 0 };

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);
    bh_vector_append(vector_ptr, "test");
    bh_vector_append(vector_ptr, "test");
    bh_vector_append(vector_ptr, "test");
    bh_vector_append(vector_ptr, "test");

    // Normally.
    EXPECT_EQ(true, bh_vector_insert(vector_ptr, 0, elem_buf));
    bh_vector_get(vector_ptr, 1, get_elem);
    EXPECT_EQ(0, strncmp(elem_buf, get_elem, 11));

    EXPECT_EQ(true, bh_vector_insert(vector_ptr, 2, elem_buf));
    EXPECT_EQ(true, bh_vector_insert(vector_ptr, 5, elem_buf));

    // Illegal parameters: nullptr.
    EXPECT_EQ(false, bh_vector_insert(nullptr, 0, nullptr));
    EXPECT_EQ(false, bh_vector_insert(vector_ptr, 0, nullptr));
    EXPECT_EQ(0, strncmp(elem_buf, get_elem, 0));
    // Illegal parameters: index >= vector->num_elems.
    EXPECT_EQ(false, bh_vector_insert(vector_ptr, 10, elem_buf));

    // "if (!extend_vector(vector, vector->num_elems + 1))" == true.
    vector_ptr->num_elems = UINT32_MAX + 1;
    EXPECT_EQ(false, bh_vector_insert(vector_ptr, 2, elem_buf));

    // use_lock is false.
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), false);
    bh_vector_append(vector_ptr, "test");
    EXPECT_EQ(true, bh_vector_insert(vector_ptr, 0, elem_buf));
}

TEST_F(bh_vector_test_suite, bh_vector_append)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";
    char get_elem[12] = { 0 };

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);

    // Normally.
    EXPECT_EQ(true, bh_vector_append(vector_ptr, elem_buf));
    bh_vector_get(vector_ptr, 0, get_elem);
    EXPECT_EQ(0, strncmp(elem_buf, get_elem, 11));

    // Illegal parameters: nullptr.
    EXPECT_EQ(false, bh_vector_append(nullptr, nullptr));
    EXPECT_EQ(false, bh_vector_append(vector_ptr, nullptr));
}

TEST_F(bh_vector_test_suite, bh_vector_remove)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";
    char old_elem[12] = { 0 };

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);
    bh_vector_append(vector_ptr, elem_buf);
    bh_vector_append(vector_ptr, elem_buf);
    bh_vector_append(vector_ptr, elem_buf);
    bh_vector_append(vector_ptr, elem_buf);

    // Normally.
    // Remove the first one.
    EXPECT_EQ(true, bh_vector_remove(vector_ptr, 0, old_elem));
    // Remove the middle one.
    EXPECT_EQ(true, bh_vector_remove(vector_ptr, 2, old_elem));
    // Remove the last one.
    EXPECT_EQ(true, bh_vector_remove(vector_ptr, 1, old_elem));

    EXPECT_EQ(true, bh_vector_remove(vector_ptr, 0, nullptr));

    // Illegal parameters: nullptr.
    EXPECT_EQ(false, bh_vector_remove(nullptr, 0, nullptr));
    EXPECT_EQ(false, bh_vector_remove(vector_ptr, 0, nullptr));
    // Illegal parameters: index >= vector->num_elems.
    EXPECT_EQ(false, bh_vector_remove(vector_ptr, 1, old_elem));

    // use_lock is false.
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), false);
    bh_vector_append(vector_ptr, elem_buf);
    EXPECT_EQ(true, bh_vector_remove(vector_ptr, 0, old_elem));
}

TEST_F(bh_vector_test_suite, bh_vector_size)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);
    bh_vector_append(vector_ptr, elem_buf);

    EXPECT_EQ(1, bh_vector_size(vector_ptr));
    EXPECT_EQ(0, bh_vector_size(nullptr));
}

TEST_F(bh_vector_test_suite, bh_vector_destroy)
{
    Vector *vector_ptr = nullptr;
    char elem_buf[] = "test_vector";

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), true);
    bh_vector_append(vector_ptr, elem_buf);

    // Normally.
    EXPECT_EQ(true, bh_vector_destroy(vector_ptr));
    // Illegal parameters: nullptr.
    EXPECT_EQ(false, bh_vector_destroy(nullptr));

    // use_lock is false.
    bh_vector_init(vector_ptr, 6, sizeof(elem_buf), false);
    bh_vector_append(vector_ptr, elem_buf);
    EXPECT_EQ(true, bh_vector_destroy(vector_ptr));
}

TEST_F(bh_vector_test_suite, bh_vector_thread_safety)
{
    Vector *vector_ptr = nullptr;
    char elem;
    int32_t i = 0;
    std::vector<std::future<void>> threads;

    vector_ptr = (Vector *)wasm_runtime_malloc(sizeof(Vector));
    memset(vector_ptr, 0, sizeof(Vector));
    bh_vector_init(vector_ptr, 6, sizeof(elem), true);

    for (i = 0; i < 8; i++) {
        threads.push_back(std::async([&] {
            for (int j = 0; j < 25; j++) {
                bh_vector_append(vector_ptr, (void *)&elem);
            }
        }));
    }

    for (auto &t : threads) {
        t.wait();
    }

    EXPECT_EQ(bh_vector_size(vector_ptr), 200);

    // Normally.
    EXPECT_EQ(true, bh_vector_destroy(vector_ptr));
}
