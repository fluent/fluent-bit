# Copyright (C) 2019-21 Intel Corporation and others.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# from ESP-IDF 4.0 examples/build_system/cmake/idf_as_lib
cmake_minimum_required(VERSION 3.5)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set (COMPONENTS ${IDF_TARGET} main freertos esptool_py wamr)
list(APPEND EXTRA_COMPONENT_DIRS "$ENV{WAMR_PATH}/build-scripts/esp-idf")

project(wamr-simple)