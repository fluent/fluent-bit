/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"

#include "test_helper.h"
#include "gtest/gtest.h"

class bh_list_test_suite : public testing::Test
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

TEST_F(bh_list_test_suite, bh_list_init)
{
    bh_list list_test;

    // Normally.
    EXPECT_EQ(BH_LIST_SUCCESS, bh_list_init(&list_test));

    // Illegal parameters.
    EXPECT_EQ(BH_LIST_ERROR, bh_list_init(nullptr));
}

TEST_F(bh_list_test_suite, bh_list_insert)
{
    bh_list list_test;
    bh_list_link elem_insert;

    // Normally.
    bh_list_init(&list_test);
    EXPECT_EQ(BH_LIST_SUCCESS, bh_list_insert(&list_test, &elem_insert));

    // Illegal parameters.
    EXPECT_EQ(BH_LIST_ERROR, bh_list_insert(nullptr, nullptr));
    EXPECT_EQ(BH_LIST_ERROR, bh_list_insert(&list_test, nullptr));
}

TEST_F(bh_list_test_suite, bh_list_remove)
{
    bh_list list_test;
    bh_list_link elem_insert_1;
    bh_list_link elem_insert_2;
    bh_list_link elem_insert_3;
    bh_list_link elem_insert_4;

    // Normally.
    bh_list_init(&list_test);
    bh_list_insert(&list_test, &elem_insert_1);
    bh_list_insert(&list_test, &elem_insert_2);
    bh_list_insert(&list_test, &elem_insert_3);
    bh_list_insert(&list_test, &elem_insert_4);
    EXPECT_EQ(BH_LIST_SUCCESS, bh_list_remove(&list_test, &elem_insert_1));

    // The elem specified by parameter is not in the list.
    EXPECT_EQ(BH_LIST_ERROR, bh_list_remove(&list_test, &elem_insert_1));

    // Illegal parameters.
    EXPECT_EQ(BH_LIST_ERROR, bh_list_remove(&list_test, nullptr));
    EXPECT_EQ(BH_LIST_ERROR, bh_list_remove(nullptr, nullptr));
    EXPECT_EQ(BH_LIST_ERROR, bh_list_remove(nullptr, &elem_insert_1));
}

TEST_F(bh_list_test_suite, bh_list_length)
{
    bh_list list_test;
    bh_list_link elem_insert_1;
    bh_list_link elem_insert_2;

    bh_list_init(&list_test);

    // The length is 0.
    EXPECT_EQ(0, bh_list_length(&list_test));

    // The length is 2.
    bh_list_insert(&list_test, &elem_insert_1);
    bh_list_insert(&list_test, &elem_insert_2);
    EXPECT_EQ(2, bh_list_length(&list_test));

    // Illegal parameters.
    EXPECT_EQ(0, bh_list_length(nullptr));
}

TEST_F(bh_list_test_suite, bh_list_first_elem)
{
    bh_list list_test;
    bh_list_link elem_insert_1;
    bh_list_link elem_insert_2;

    bh_list_init(&list_test);

    // There is no element in the list.
    EXPECT_EQ(nullptr, bh_list_first_elem(&list_test));

    // There are 2 elements in the list.
    bh_list_insert(&list_test, &elem_insert_1);
    bh_list_insert(&list_test, &elem_insert_2);
    EXPECT_EQ(&elem_insert_2, bh_list_first_elem(&list_test));

    // Illegal parameters.
    EXPECT_EQ(nullptr, bh_list_first_elem(nullptr));
}

TEST_F(bh_list_test_suite, bh_list_elem_next)
{
    bh_list list_test;
    bh_list_link elem_insert_1;
    bh_list_link elem_insert_2;

    bh_list_init(&list_test);
    bh_list_insert(&list_test, &elem_insert_1);
    bh_list_insert(&list_test, &elem_insert_2);

    // Normally.
    EXPECT_EQ(&elem_insert_1, bh_list_elem_next(&elem_insert_2));

    // Illegal parameters.
    EXPECT_EQ(nullptr, bh_list_elem_next(nullptr));
}
