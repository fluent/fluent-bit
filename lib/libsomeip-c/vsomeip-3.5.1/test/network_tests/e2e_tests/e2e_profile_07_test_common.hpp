// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef E2E_PROFILE_07_TEST_COMMON_HPP_
#define E2E_PROFILE_07_TEST_COMMON_HPP_

#include <vsomeip/vsomeip.hpp>

const vsomeip::service_t PROFILE_07_SERVICE = 0xd025;
const vsomeip::instance_t PROFILE_07_INSTANCE = 0x0001;
const vsomeip::major_version_t PROFILE_07_MAJOR = 0x01;
const vsomeip::minor_version_t PROFILE_07_MINOR = 0x00000000;

const vsomeip::method_t PROFILE_07_METHOD = 0x0001;
const vsomeip::method_t PROFILE_07_SHUTDOWN = 0x0002;

const vsomeip::eventgroup_t PROFILE_07_EVENTGROUP = 0x0001;
const vsomeip::event_t PROFILE_07_EVENT = 0x8001;

#define PROFILE_07_NUM_MESSAGES 3

#endif // E2E_PROFILE_07_TEST_COMMON_HPP_
