// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef MEMORY_TEST_COMMON_HPP_
#define MEMORY_TEST_COMMON_HPP_

#include <vsomeip/vsomeip.hpp>

constexpr vsomeip::service_t MEMORY_SERVICE = 0xb519;
constexpr vsomeip::instance_t MEMORY_INSTANCE = 0x0001;
constexpr vsomeip::method_t MEMORY_START_METHOD = 0x0998;
constexpr vsomeip::method_t MEMORY_STOP_METHOD = 0x0999;
constexpr vsomeip::event_t MEMORY_EVENT = 0x8008;
constexpr vsomeip::eventgroup_t MEMORY_EVENTGROUP = 0x0005;
constexpr vsomeip::major_version_t MEMORY_MAJOR = 0x01;
constexpr vsomeip::minor_version_t MEMORY_MINOR = 0x01;

constexpr auto MEMORY_CHECKER_INTERVAL = std::chrono::seconds(5);
constexpr auto MESSAGE_SENDER_INTERVAL = std::chrono::milliseconds(5);
constexpr auto WATCHDOG_INTERVAL = std::chrono::seconds(2);
constexpr auto WAIT_AVAILABILITY = std::chrono::milliseconds(15000);
constexpr auto WAIT_START_MESSAGE = std::chrono::milliseconds(10000);
constexpr auto WAIT_STOP_MESSAGE = std::chrono::seconds(30);

constexpr uint16_t TEST_EVENT_NUMBER = 20;
constexpr uint16_t TEST_MESSAGE_NUMBER = 9000;
constexpr int NOTIFY_PAYLOAD_SIZE = 4000;
constexpr double MEMORY_LOAD_LIMIT = 1.15; // meaning 15% limit above the average value

#endif // MEMORY_TEST_COMMON_HPP_
