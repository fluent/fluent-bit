// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef EVENT_TEST_GLOBALS_HPP_
#define EVENT_TEST_GLOBALS_HPP_

namespace event_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::method_t method_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t eventgroup_id;
    vsomeip::method_t shutdown_method_id;
    vsomeip::method_t notify_method_id;
};

struct service_info service = { 0x3344, 0x1, 0x1111, 0x8002, 0x1, 0x1404, 0x4242 };

enum test_mode_e : std::uint8_t {
    UNKNOWN,
    PAYLOAD_FIXED,
    PAYLOAD_DYNAMIC
};

std::uint32_t payload_fixed_length = 20;

}

#endif /* EVENT_TEST_GLOBALS_HPP_ */
