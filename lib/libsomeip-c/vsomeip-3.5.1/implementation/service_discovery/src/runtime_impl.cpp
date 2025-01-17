// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/defines.hpp>
#include <vsomeip/message.hpp>

#include "../include/constants.hpp"
#include "../include/defines.hpp"
#include "../include/message_impl.hpp"
#include "../include/runtime_impl.hpp"
#include "../include/service_discovery_impl.hpp"

VSOMEIP_PLUGIN(vsomeip_v3::sd::runtime_impl)

namespace vsomeip_v3 {
namespace sd {

runtime_impl::runtime_impl()
    : plugin_impl("vsomeip SD plug-in", 1, plugin_type_e::SD_RUNTIME_PLUGIN) {
}

runtime_impl::~runtime_impl() {
}

std::shared_ptr<service_discovery>
runtime_impl::create_service_discovery(service_discovery_host *_host,
        std::shared_ptr<configuration> _configuration) const {
    return std::make_shared<service_discovery_impl>(_host, _configuration);
}

} // namespace sd
} // namespace vsomeip_v3
