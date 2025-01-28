// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_RUNTIME_IMPL_HPP_
#define VSOMEIP_V3_SD_RUNTIME_IMPL_HPP_

#include <vsomeip/plugin.hpp>
#include "runtime.hpp"

namespace vsomeip_v3 {
namespace sd {

class runtime_impl
        : public runtime,
          public plugin_impl<runtime_impl> {
public:
    runtime_impl();
    virtual ~runtime_impl();

    std::shared_ptr<service_discovery> create_service_discovery(
            service_discovery_host *_host,
            std::shared_ptr<configuration> _configuration) const;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_RUNTIME_IMPL_HPP_

