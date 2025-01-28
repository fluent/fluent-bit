# Copyright (C) 2015-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project("unit_tests_bin" LANGUAGES CXX)

add_subdirectory(message_payload_impl_tests)
add_subdirectory(message_serializer_tests)
add_subdirectory(message_deserializer_tests)
add_subdirectory(protocol_tests)
add_subdirectory(routing_manager_tests)
add_subdirectory(security_policy_manager_impl_tests)
add_subdirectory(security_policy_tests)
add_subdirectory(security_tests)
add_subdirectory(utility_utility_tests)
