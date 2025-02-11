// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_DEBOUNCE_HPP
#define VSOMEIP_V3_DEBOUNCE_HPP

#include <vsomeip/structured_types.hpp>

namespace vsomeip_v3 {

// Additionally store the last forwarded timestamp to
// avoid having to lock
struct debounce_filter_impl_t : debounce_filter_t {
    debounce_filter_impl_t()
        : last_forwarded_(std::chrono::steady_clock::time_point::max()) {
    }

    explicit debounce_filter_impl_t(const debounce_filter_t &_source)
        : debounce_filter_t(_source),
          last_forwarded_(std::chrono::steady_clock::time_point::max()) {
    }

    std::chrono::steady_clock::time_point last_forwarded_;
};

using debounce_configuration_t =
    std::map<service_t,
        std::map<instance_t,
            std::map<event_t,
                std::shared_ptr<debounce_filter_impl_t>>>>;

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_DEBOUNCE_HPP
