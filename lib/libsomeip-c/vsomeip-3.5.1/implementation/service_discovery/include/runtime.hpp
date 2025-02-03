// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_RUNTIME_HPP_
#define VSOMEIP_V3_SD_RUNTIME_HPP_

#include <memory>

namespace vsomeip_v3 {

class configuration;

namespace sd {

class message_impl;
class service_discovery;
class service_discovery_host;

class runtime {
public:
    virtual ~runtime()
#ifndef ANDROID
    {}
#else
    ;
#endif

    virtual std::shared_ptr<service_discovery> create_service_discovery(
            service_discovery_host *_host,
            std::shared_ptr<configuration> _configuration) const = 0;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_RUNTIME_HPP_
