// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef SOMEIP_TP_TEST_GLOBALS_HPP_
#define SOMEIP_TP_TEST_GLOBALS_HPP_

#include <vsomeip/primitive_types.hpp>

namespace someip_tp_test {

struct service_info {
    vsomeip::service_t service_id;
    vsomeip::instance_t instance_id;
    vsomeip::method_t method_id;
    vsomeip::event_t event_id;
    vsomeip::eventgroup_t eventgroup_id;
    vsomeip::method_t shutdown_method_id;
    vsomeip::method_t notify_method_id;
};

struct service_info service = { 0x4545, 0x1, 0x4545, 0x8001, 0x1, 0x4501, 0x4502 };
struct service_info service_slave = { 0x6767, 0x1, 0x6767, 0x8001, 0x1, 0x6701, 0x6702 };

enum test_mode_e {
    IN_SEQUENCE,
    MIXED,
    INCOMPLETE,
    DUPLICATE,
    OVERLAP,
    OVERLAP_FRONT_BACK
};

const std::uint32_t number_of_fragments = 6;
const std::uint32_t max_segment_size = 1392;

}

#endif /* SOMEIP_TP_TEST_GLOBALS_HPP_ */
