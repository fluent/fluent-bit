// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef OFFER_TEST_GLOBALS_HPP_
#define OFFER_TEST_GLOBALS_HPP_

namespace offer_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::method_t method_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t eventgroup_id;
    vsomeip::method_t shutdown_method_id;
};

uint8_t num_all_offered_services = 5;
uint8_t num_local_offered_services = 2;
uint8_t num_remote_offered_services = 3;


struct service_info service         = { 0x1111, 0x1, 0x1111, 0x1111, 0x1000, 0x1404 };
struct service_info remote_service  = { 0x2222, 0x2, 0x2222, 0x2222, 0x2000, 0x2808 };
}

#endif /* OFFER_TEST_GLOBALS_HPP_ */
