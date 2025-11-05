# Copyright (C) 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

create_wamr_unit_test(wasi_threads
    ${CMAKE_CURRENT_LIST_DIR}/test_tid_allocator.cpp
)
