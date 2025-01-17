# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(header_factory_tests LANGUAGES CXX)

# Configure necessary files into the build directory.
set(configuration_files
    header_factory_test_client.json
    header_factory_test_client_start.sh
    header_factory_test_send_receive_starter.sh
    header_factory_test_service.json
    header_factory_test_service_start.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(header_factory_test
    header_factory_test.cpp
)

# Add test executable.
add_executable(header_factory_test_client
    header_factory_test_client.cpp
)

# Add test executable.
add_executable(header_factory_test_service
    header_factory_test_service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    header_factory_test
    header_factory_test_client
    header_factory_test_service
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Link thread libraries to executables.
foreach(target ${executables})
    target_link_libraries(${target}
        ${CMAKE_THREAD_LIBS_INIT}
    )
endforeach()

# Add custom test command.
add_custom_test(
    NAME header_factory_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/header_factory_test
)

# Add custom test command.
add_custom_test(
    NAME header_factory_test_send_receive
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/header_factory_test_send_receive_starter.sh
)
