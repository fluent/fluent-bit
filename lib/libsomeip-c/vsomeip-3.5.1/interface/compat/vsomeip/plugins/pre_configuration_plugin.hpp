// Copyright (C) 2016-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_PRE_CONFIGURATION_PLUGIN_HPP
#define VSOMEIP_PRE_CONFIGURATION_PLUGIN_HPP

#include "../../../compat/vsomeip/export.hpp"

// Version should be incremented on breaking API change
#define VSOMEIP_PRE_CONFIGURATION_PLUGIN_VERSION              1

namespace vsomeip {
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
}

#endif // VSOMEIP_PRE_CONFIGURATION_PLUGIN_HPP
