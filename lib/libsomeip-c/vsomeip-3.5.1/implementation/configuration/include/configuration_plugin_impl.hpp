// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_CONFIGURATION_CONFIGURATION_PLUGIN_IMPL_HPP_
#define VSOMEIP_V3_CONFIGURATION_CONFIGURATION_PLUGIN_IMPL_HPP_

#include <map>
#include <mutex>

#include <vsomeip/plugin.hpp>

#include "configuration_plugin.hpp"

namespace vsomeip_v3 {
namespace cfg {

    class configuration_impl;

} // namespace cfg

class configuration_plugin_impl
    : public configuration_plugin,
      public plugin_impl<configuration_plugin_impl> {
public:
    configuration_plugin_impl();
    virtual ~configuration_plugin_impl();

    std::shared_ptr<configuration> get_configuration(const std::string &_name,
            const std::string &_path);
    bool remove_configuration(const std::string &_name);

private:
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<cfg::configuration_impl> > configurations_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_CONFIGURATION_CONFIGURATION_PLUGIN_IMPL_HPP_
