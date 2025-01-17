// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef BIG_PAYLOAD_TEST_GLOBALS_HPP_
#define BIG_PAYLOAD_TEST_GLOBALS_HPP_

#include <cstdint>

namespace big_payload_test {
    constexpr std::uint32_t BIG_PAYLOAD_SIZE = 1024*600;
    constexpr std::uint32_t BIG_PAYLOAD_SIZE_UDP = 1024*30;
    constexpr std::uint32_t BIG_PAYLOAD_SIZE_RANDOM = 1024*1024*10;
    constexpr vsomeip::byte_t DATA_SERVICE_TO_CLIENT = 0xAA;
    constexpr vsomeip::byte_t DATA_CLIENT_TO_SERVICE = 0xFF;

    constexpr std::uint32_t BIG_PAYLOAD_TEST_NUMBER_MESSAGES = 10;
    constexpr std::uint32_t BIG_PAYLOAD_TEST_NUMBER_MESSAGES_RANDOM = 50;

    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID = 0x1234;
    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID_LIMITED = 0x1235;
    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID_RANDOM = 0x1236;
    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID_LIMITED_GENERAL = 0x1237;
    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID_QUEUE_LIMITED_GENERAL = 0x1238;
    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID_QUEUE_LIMITED_SPECIFIC = 0x1239;
    constexpr vsomeip::service_t TEST_SERVICE_SERVICE_ID_UDP = 0x1240;

    constexpr vsomeip::service_t TEST_SERVICE_INSTANCE_ID = 0x1;
    constexpr vsomeip::method_t TEST_SERVICE_METHOD_ID = 0x8421;

    enum test_mode {
        RANDOM,
        LIMITED,
        LIMITED_GENERAL,
        QUEUE_LIMITED_GENERAL,
        QUEUE_LIMITED_SPECIFIC,
        UDP,
        UNKNOWN
    };
}

#endif /* BIG_PAYLOAD_TEST_GLOBALS_HPP_ */
