#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# ./c_api_unit_test --gtest_list_tests

function run_one()
{
  local case=$1
  valgrind --tool=memcheck --leak-check=yes -v \
    ./c_api_unit_test --gtest_filter=CApiTests.${case}
}

function run()
{
  valgrind --tool=memcheck --leak-check=yes -v \
    ./c_api_unit_test
}

[[ $# -gt 0 ]] && $@ || run
