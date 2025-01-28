// Copyright (C) 2020 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef E2E_PROFILE_04_TEST_COMMON_HPP_
#define E2E_PROFILE_04_TEST_COMMON_HPP_

#include <vsomeip/vsomeip.hpp>

const vsomeip::service_t PROFILE_04_SERVICE = 0xd025;
const vsomeip::instance_t PROFILE_04_INSTANCE = 0x0001;
const vsomeip::major_version_t PROFILE_04_MAJOR = 0x01;
const vsomeip::minor_version_t PROFILE_04_MINOR = 0x00000000;

const vsomeip::method_t PROFILE_04_METHOD = 0x0001;
const vsomeip::method_t PROFILE_04_SHUTDOWN = 0x0002;

const vsomeip::eventgroup_t PROFILE_04_EVENTGROUP = 0x0001;
const vsomeip::event_t PROFILE_04_EVENT = 0x8001;

#define PROFILE_O4_NUM_MESSAGES 3

#endif // E2E_PROFILE_04_TEST_COMMON_HPP_
