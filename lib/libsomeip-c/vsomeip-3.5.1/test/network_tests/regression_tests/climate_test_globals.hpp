// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_EXAMPLES_SAMPLE_IDS_HPP
#define VSOMEIP_EXAMPLES_SAMPLE_IDS_HPP

namespace climate_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::method_t method_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t eventgroup_id;
    vsomeip::method_t get_method_id;
    vsomeip::method_t shutdown_method_id;
};

struct service_info service = { 0x1234, 0x5678, 0x0421, 0x8778, 0x4465, 0x0001, 0x0002};

constexpr std::chrono::seconds OFFER_CYCLE_INTERVAL = std::chrono::seconds(1);
constexpr std::chrono::milliseconds MSG_SEND_WAIT_INTERVAL = std::chrono::milliseconds(500);
}

#endif // VSOMEIP_EXAMPLES_SAMPLE_IDS_HPP
