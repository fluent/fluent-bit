# Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.

# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

set(src
  ${src}
  raw_msgpack_api.c
  )

find_package (Threads)
# add_executable(raw_msgpack_api_test ${src})
# target_link_libraries(raw_msgpack_api_test fluent-bit-shared)
# target_link_libraries(raw_msgpack_api_test ${CMAKE_THREAD_LIBS_INIT})

add_library(raw_msgpack_api SHARED ${src})
target_link_libraries(raw_msgpack_api fluent-bit-shared)
target_link_libraries(raw_msgpack_api ${CMAKE_THREAD_LIBS_INIT})

