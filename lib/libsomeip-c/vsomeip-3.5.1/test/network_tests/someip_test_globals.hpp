// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef SOMEIP_TEST_GLOBALS_HPP_
#define SOMEIP_TEST_GLOBALS_HPP_

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#ifdef USE_DLT
#ifndef ANDROID
#include <dlt/dlt.h>
#endif
#endif

namespace vsomeip_test
{

// Service
constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID = 0x1234;
constexpr vsomeip::instance_t TEST_SERVICE_INSTANCE_ID = 0x5678;
constexpr vsomeip::method_t TEST_SERVICE_METHOD_ID = 0x8421;
constexpr vsomeip::method_t TEST_SERVICE_METHOD_ID_SHUTDOWN = 0x7777;
constexpr vsomeip::method_t TEST_SERVICE_DETACH_METHOD_ID_LOOP_LONG = 0x8887;
constexpr vsomeip::method_t TEST_SERVICE_DETACH_METHOD_ID_LOOP_SHORT = 0x8888;
constexpr vsomeip::method_t TEST_SERVICE_DETACH_METHOD_ID = 0x8889;
constexpr vsomeip::client_t TEST_SERVICE_CLIENT_ID = 0x1277;

// Client local
constexpr vsomeip::client_t TEST_CLIENT_CLIENT_ID = 0x1255;

// Client external
constexpr vsomeip::client_t TEST_CLIENT_EXTERNAL_CLIENT_ID = 0x1644;


constexpr std::uint32_t NUMBER_OF_MESSAGES_TO_SEND = 10;
constexpr vsomeip::session_t TEST_INITIAL_SESSION_ID = 0x1;

constexpr std::uint32_t NUMBER_OF_MESSAGES_TO_SEND_PAYLOAD_TESTS = 1000;
constexpr vsomeip::byte_t PAYLOAD_TEST_DATA = 0xDD;
constexpr std::uint32_t MAX_PAYLOADSIZE = 1024*128;
// TR_SOMEIP_00061
constexpr std::uint32_t MAX_PAYLOADSIZE_UDP = 1400;

constexpr std::uint32_t NUMBER_OF_MESSAGES_TO_SEND_ROUTING_RESTART_TESTS = 32;

constexpr std::uint32_t NUMBER_OF_MESSAGES_TO_SEND_SECURITY_TESTS = 32;

constexpr std::uint32_t NUMBER_OF_CLIENTS_TO_REQUEST_SHUTDOWN = 4;
}

#endif /* SOMEIP_TEST_GLOBALS_HPP_ */
