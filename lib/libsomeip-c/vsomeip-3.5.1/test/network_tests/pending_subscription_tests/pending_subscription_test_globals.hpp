// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef PENDING_SUBSCRIPTION_TEST_GLOBALS_HPP_
#define PENDING_SUBSCRIPTION_TEST_GLOBALS_HPP_

namespace pending_subscription_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::method_t method_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t eventgroup_id;
    vsomeip::method_t shutdown_method_id;
    vsomeip::method_t notify_method_id;
};

struct service_info service = { 0x1122, 0x1, 0x1111, 0x1111, 0x1000, 0x1404, 0x4242 };

enum test_mode_e {
    SUBSCRIBE,
    SUBSCRIBE_UNSUBSCRIBE,
    UNSUBSCRIBE,
    SUBSCRIBE_UNSUBSCRIBE_NACK,
    SUBSCRIBE_UNSUBSCRIBE_SAME_PORT,
    SUBSCRIBE_RESUBSCRIBE_MIXED,
    SUBSCRIBE_STOPSUBSCRIBE_SUBSCRIBE,
    REQUEST_TO_SD
};

}

#endif /* PENDING_SUBSCRIPTION_TEST_GLOBALS_HPP_ */
