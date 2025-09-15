/*
 * Copyright (C) 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_leb128.h"
#include "gtest/gtest.h"

#include <vector>
#include <type_traits>

template<typename T>
void
run_read_leb_test(std::vector<uint8_t> data,
                  bh_leb_read_status_t expected_status, T expected_value)
{
    size_t offset = 0;
    uint64 value;
    bh_leb_read_status_t status =
        bh_leb_read(data.data(), data.data() + data.size(), sizeof(T) * 8,
                    std::is_signed<T>::value, &value, &offset);
    ASSERT_EQ(expected_status, status);
    if (status == BH_LEB_READ_SUCCESS) {
        ASSERT_EQ(data.size(), offset);
        ASSERT_EQ(expected_value, (T)value);
    }
}

TEST(bh_leb128_test_suite, read_leb_u32)
{
    run_read_leb_test<uint32>({ 0 }, BH_LEB_READ_SUCCESS,
                              0); // min value
    run_read_leb_test<uint32>({ 2 }, BH_LEB_READ_SUCCESS,
                              2); // single-byte value
    run_read_leb_test<uint32>({ 127 }, BH_LEB_READ_SUCCESS,
                              127); // max single-byte value
    run_read_leb_test<uint32>({ 128, 1 }, BH_LEB_READ_SUCCESS,
                              128); // min value with continuation bit
    run_read_leb_test<uint32>({ 160, 138, 32 }, BH_LEB_READ_SUCCESS,
                              525600); // arbitrary value
    run_read_leb_test<uint32>({ 255, 255, 255, 255, 15 }, BH_LEB_READ_SUCCESS,
                              UINT32_MAX); // max value
    run_read_leb_test<uint32>({ 255, 255, 255, 255, 16 }, BH_LEB_READ_OVERFLOW,
                              UINT32_MAX); // overflow
    run_read_leb_test<uint32>({ 255, 255, 255, 255, 128 }, BH_LEB_READ_TOO_LONG,
                              0);
    run_read_leb_test<uint32>({ 128 }, BH_LEB_READ_UNEXPECTED_END, 0);
}

TEST(bh_leb128_test_suite, read_leb_i64)
{
    run_read_leb_test<int64>({ 184, 188, 195, 159, 237, 209, 128, 2 },
                             BH_LEB_READ_SUCCESS,
                             1128712371232312); // arbitrary value
    run_read_leb_test<int64>(
        { 128, 128, 128, 128, 128, 128, 128, 128, 128, 127 },
        BH_LEB_READ_SUCCESS,
        (uint64)INT64_MIN); // min value
    run_read_leb_test<int64>({ 255, 255, 255, 255, 255, 255, 255, 255, 255, 0 },
                             BH_LEB_READ_SUCCESS,
                             INT64_MAX); // max value
}