# Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

# Configure necessary files into the build folder.
set(configuration_files
    service/vsomeip_events.json
    service/vsomeip_gen.json
    service/vsomeip_std.json
    cyclic_event_test_client.json
    cyclic_event_test_master_starter.sh
    cyclic_event_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(cyclic_event_test_service
    cyclic_event_test_service.cpp
)

# Add test executable.
add_executable(cyclic_event_test_client
    cyclic_event_test_client.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    cyclic_event_test_client
    cyclic_event_test_service
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Add custom test command.
add_custom_test(
    NAME cyclic_event_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/cyclic_event_test_master_starter.sh
    TIMEOUT 15
)
