// Copyright (C) 2019-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/internal/logger.hpp>

#include "../include/configuration_plugin_impl.hpp"
#include "../include/configuration_impl.hpp"

VSOMEIP_PLUGIN(vsomeip_v3::configuration_plugin_impl)

namespace vsomeip_v3 {

configuration_plugin_impl::configuration_plugin_impl()
    : plugin_impl("vsomeip-configuration-plugin",
            VSOMEIP_CONFIG_PLUGIN_VERSION,
            plugin_type_e::CONFIGURATION_PLUGIN) {
}

configuration_plugin_impl::~configuration_plugin_impl() {
}

std::shared_ptr<configuration>
configuration_plugin_impl::get_configuration(const std::string &_name,
        const std::string &_path) {

    std::shared_ptr<cfg::configuration_impl> its_configuration;
    std::scoped_lock its_lock(mutex_);
    auto its_iterator = configurations_.find(_name);
    if (its_iterator != configurations_.end()) {
        its_configuration = its_iterator->second;
    } else {
        its_configuration = std::make_shared<cfg::configuration_impl>(_path);
        its_configuration->load(_name);
        configurations_[_name] = its_configuration;
    }

    return its_configuration;
}

bool configuration_plugin_impl::remove_configuration(const std::string & _name) {
    std::scoped_lock its_lock(mutex_);
    return configurations_.erase(_name) > 0;
}
} // namespace vsomeip_v3
