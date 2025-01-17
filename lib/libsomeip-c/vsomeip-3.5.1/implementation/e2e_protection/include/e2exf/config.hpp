// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2EXF_CONFIG_HPP
#define VSOMEIP_V3_E2EXF_CONFIG_HPP

#include <vsomeip/primitive_types.hpp>
#include "../e2e/profile/profile_interface/checker.hpp"
#include "../e2e/profile/profile_interface/protector.hpp"

#include <memory>
#include <map>

namespace vsomeip_v3 {
namespace e2exf {

using data_identifier_t = std::pair<service_t, event_t>;

std::ostream &operator<<(std::ostream &_os, const e2exf::data_identifier_t &_data_identifier);

} // namespace e2exf
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2EXF_CONFIG_HPP
