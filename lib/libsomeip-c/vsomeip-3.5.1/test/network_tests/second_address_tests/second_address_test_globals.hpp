// Copyright (C) 2014-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef SECOND_ADDRESS_TEST_GLOBALS_HPP_
#define SECOND_ADDRESS_TEST_GLOBALS_HPP_

namespace second_address_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::eventgroup_t eventgroup_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t selective_eventgroup_id;
    vsomeip::event_t selective_event_id;
    vsomeip::method_t request_method_id;
    vsomeip::method_t notify_method_id;
    vsomeip::method_t shutdown_method_id;
};

struct service_info service = { 0x3333, 0x1, 0x1, 0x3301, 0x2, 0x3302, 0x1111, 0x2222, 0x1404 };

static constexpr std::uint32_t number_of_messages_to_send = 150;
static constexpr std::uint8_t number_of_events_to_send = 150;
}

#endif /* SECOND_ADDRESS_TEST_GLOBALS_HPP_ */
