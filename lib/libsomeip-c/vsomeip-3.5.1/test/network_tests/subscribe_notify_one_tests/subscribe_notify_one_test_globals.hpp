// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef SUBSCRIBE_NOTIFY_TEST_GLOBALS_HPP_
#define SUBSCRIBE_NOTIFY_TEST_GLOBALS_HPP_

namespace subscribe_notify_one_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::method_t method_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t eventgroup_id;
};

static constexpr std::array<service_info, 7> service_infos = {{
        // placeholder to be consistent w/ client ids, service ids, app names
        { 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF },
        // node 1
        { 0x1111, 0x1, 0x1111, 0x1111, 0x1000 },
        { 0x2222, 0x1, 0x2222, 0x2222, 0x2000 },
        { 0x3333, 0x1, 0x3333, 0x3333, 0x3000 },
        // node 2
        { 0x4444, 0x1, 0x4444, 0x4444, 0x4000 },
        { 0x5555, 0x1, 0x5555, 0x5555, 0x5000 },
        { 0x6666, 0x1, 0x6666, 0x6666, 0x6000 }
}};

static constexpr int notifications_to_send = 10;
}

#endif /* SUBSCRIBE_NOTIFY_TEST_GLOBALS_HPP_ */
