// Copyright (C) 2020 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef DEBOUNCE_TEST_COMMON_HPP_
#define DEBOUNCE_TEST_COMMON_HPP_

#include <vsomeip/vsomeip.hpp>

const vsomeip::service_t DEBOUNCE_SERVICE = 0xb657;
const vsomeip::instance_t DEBOUNCE_INSTANCE = 0x0003;
const vsomeip::method_t DEBOUNCE_START_METHOD = 0x0998;
const vsomeip::method_t DEBOUNCE_STOP_METHOD = 0x0999;
const vsomeip::event_t DEBOUNCE_EVENT = 0x8001;
const vsomeip::event_t DEBOUNCE_EVENT_2 = 0x8002;
const vsomeip::event_t DEBOUNCE_EVENT_4 = 0x8004;
const vsomeip::eventgroup_t DEBOUNCE_EVENTGROUP = 0x0005;
const vsomeip::major_version_t DEBOUNCE_MAJOR = 0x01;
const vsomeip::minor_version_t DEBOUNCE_MINOR = 0x01;

enum debounce_test_id_e : uint8_t {
    DTI_FLAT = 0x00,
    DTI_INCREASE = 0x01,
    DTI_DECREASE = 0x02,
    DTI_MASK = 0x03
};

#endif // DEBOUNCE_TEST_COMMON_HPP_
