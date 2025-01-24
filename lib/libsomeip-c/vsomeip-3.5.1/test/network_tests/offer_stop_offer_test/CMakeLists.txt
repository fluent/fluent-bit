# Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)
if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "QNX")
# Configure necessary files into the build folder.
set(configuration_files
    offer_stop_offer_test_client.json
    offer_stop_offer_test_client_starter.sh
    offer_stop_offer_test_service.json
    offer_stop_offer_test_service_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(offer_stop_offer_test_client
    offer_stop_offer_test_client.cpp
    applications/client.cpp
)

# Add test executable.
add_executable(offer_stop_offer_test_service
    offer_stop_offer_test_service.cpp
    applications/service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    offer_stop_offer_test_client
    offer_stop_offer_test_service
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME offer_stop_offer_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/offer_stop_offer_test_client_starter.sh
    TIMEOUT 30
)
endif()
