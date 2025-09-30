# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

message(STATUS "involving boringssl...")

include(ExternalProject)

ExternalProject_Add(boringssl
  PREFIX          external/boringssl
  # follow envoy, which tracks BoringSSL, which tracks Chromium
  # https://github.com/envoyproxy/envoy/blob/main/bazel/repository_locations.bzl#L112
  # chromium-105.0.5195.37 (linux/beta)
  URL             https://github.com/google/boringssl/archive/098695591f3a2665fccef83a3732ecfc99acdcdd.tar.gz
  URL_HASH        SHA256=e141448cf6f686b6e9695f6b6459293fd602c8d51efe118a83106752cf7e1280
  DOWNLOAD_EXTRACT_TIMESTAMP NEW
  # SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/../external/boringssl
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/src/boringssl-build/libssl.a
                      ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/
                    && ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/src/boringssl-build/libcrypto.a
                      ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/
                    && ${CMAKE_COMMAND} -E create_symlink ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/src/boringssl/src/include/openssl
                      ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/openssl
)

add_library(boringssl_ssl STATIC IMPORTED GLOBAL)
set_target_properties(
  boringssl_ssl
  PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/libssl.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/
)
add_dependencies(boringssl_ssl boringssl)

add_library(boringssl_crypto STATIC IMPORTED GLOBAL)
set_target_properties(
  boringssl_crypto
  PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/libcrypto.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/external/boringssl/
)
add_dependencies(boringssl_crypto boringssl)