// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CONFIGURATION_PLUGIN_HPP_
#define VSOMEIP_V3_CONFIGURATION_PLUGIN_HPP_

#include <string>
#include <memory>

#define VSOMEIP_CONFIG_PLUGIN_VERSION              1

namespace vsomeip_v3 {

class configuration;

class configuration_plugin {
public:
    virtual ~configuration_plugin() = default;
    virtual std::shared_ptr<configuration> get_configuration(
            const std::string &_name, const std::string &_path) = 0;
    virtual bool remove_configuration(const std::string &_name) = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CONFIGURATION_PLUGIN_HPP_
