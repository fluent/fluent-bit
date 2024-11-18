// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_APPLICATION_PLUGIN_HPP_
#define VSOMEIP_V3_APPLICATION_PLUGIN_HPP_

#include <string>
#include <memory>

#include <vsomeip/export.hpp>

// Version should be incremented on breaking API change
#define VSOMEIP_APPLICATION_PLUGIN_VERSION              1

namespace vsomeip_v3 {

enum class application_plugin_state_e : uint8_t {
    STATE_INITIALIZED,
    STATE_STARTED,
    STATE_STOPPED
};

/**
 * The application plug-in can be used to extend application behavior
 * via an module/plug-in.
 */
class application_plugin {
public:
    virtual ~application_plugin() {}

    // Called by vSomeIP to inform an application plug-in about its actual state
    // Call should not be blocked from plug-in as there is no threading.
    // The caller thread of "application::init/::start/::stop" will inform the plug-in.
    virtual void on_application_state_change(const std::string _application_name,
            const application_plugin_state_e _app_state) = 0;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_APPLICATION_PLUGIN_HPP_
