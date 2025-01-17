// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_PRE_CONFIGURATION_PLUGIN_HPP_
#define VSOMEIP_V3_PRE_CONFIGURATION_PLUGIN_HPP_

#include <vsomeip/export.hpp>

// Version should be incremented on breaking API change
#define VSOMEIP_PRE_CONFIGURATION_PLUGIN_VERSION              1

namespace vsomeip_v3 {
/**
 * The pre configuration plug-in can be used to extend configuration load behavior
 * via an module/plug-in.
 */
class pre_configuration_plugin {
public:
    virtual ~pre_configuration_plugin() {}

    // Plug-In should return a valid path to a vSomeIP configuration.
    // vSomeIP will use this path for config loading if such a plug-in is availablel.
    virtual std::string get_configuration_path() = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PRE_CONFIGURATION_PLUGIN_HPP_
