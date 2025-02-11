// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

namespace cpu_load_test {

static constexpr vsomeip::service_t service_id(0x1111);
static constexpr vsomeip::instance_t instance_id(0x1);
static constexpr vsomeip::method_t method_id(0x1111);
static constexpr vsomeip::byte_t load_test_data(0xDD);
static constexpr vsomeip::length_t default_payload_length(40);
static constexpr vsomeip::method_t method_id_shutdown(0x7777);
static constexpr vsomeip::method_t method_id_cpu_measure_start(0x8888);
static constexpr vsomeip::method_t method_id_cpu_measure_stop(0x9999);
}
