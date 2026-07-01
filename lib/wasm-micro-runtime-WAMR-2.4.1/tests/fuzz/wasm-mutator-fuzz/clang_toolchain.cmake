# Copyright (C) 2025 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Check for Clang C compiler
find_program(CLANG_C_COMPILER NAMES clang)
if(NOT CLANG_C_COMPILER)
    message(FATAL_ERROR "Clang C compiler not found. Please install Clang.")
else()
    message(STATUS "Clang C compiler found: ${CLANG_C_COMPILER}")
    set(CMAKE_C_COMPILER ${CLANG_C_COMPILER})
endif()

# Check for Clang C++ compiler
find_program(CLANG_CXX_COMPILER NAMES clang++)
if(NOT CLANG_CXX_COMPILER)
    message(FATAL_ERROR "Clang C++ compiler not found. Please install Clang.")
else()
    message(STATUS "Clang C++ compiler found: ${CLANG_CXX_COMPILER}")
    set(CMAKE_CXX_COMPILER ${CLANG_CXX_COMPILER})
endif()

# Check for Clang assembler
find_program(CLANG_ASM_COMPILER NAMES clang)
if(NOT CLANG_ASM_COMPILER)
    message(FATAL_ERROR "Clang assembler not found. Please install Clang.")
else()
    message(STATUS "Clang assembler found: ${CLANG_ASM_COMPILER}")
    set(CMAKE_ASM_COMPILER ${CLANG_ASM_COMPILER})
endif()
