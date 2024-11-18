// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_BUFFER_HPP_
#define VSOMEIP_V3_BUFFER_HPP_

#include <array>
#include <chrono>
#include <memory>
#include <set>

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/defines.hpp>
#include <vsomeip/primitive_types.hpp>

#if defined(_WIN32) && !defined(_MSVC_LANG)
    #define DEFAULT_NANOSECONDS_MAX 1000000000
#else
    #define DEFAULT_NANOSECONDS_MAX std::chrono::nanoseconds::max()
#endif

namespace vsomeip_v3 {

typedef std::vector<byte_t> message_buffer_t;
typedef std::shared_ptr<message_buffer_t> message_buffer_ptr_t;

#if 0
struct timing {
    timing() : debouncing_(0), maximum_retention_(DEFAULT_NANOSECONDS_MAX) {};

    std::chrono::nanoseconds debouncing_;
    std::chrono::nanoseconds maximum_retention_;
};
#endif

struct train {
    train()
        : buffer_(std::make_shared<message_buffer_t>()),
          minimal_debounce_time_(DEFAULT_NANOSECONDS_MAX),
          minimal_max_retention_time_(DEFAULT_NANOSECONDS_MAX),
          departure_(std::chrono::steady_clock::now() + std::chrono::hours(6)) {
    };

    void reset() {
        buffer_ = std::make_shared<message_buffer_t>();
        passengers_.clear();
        minimal_debounce_time_ = DEFAULT_NANOSECONDS_MAX;
        minimal_max_retention_time_ = DEFAULT_NANOSECONDS_MAX;
        departure_ = std::chrono::steady_clock::now() + std::chrono::hours(6);
    }

    message_buffer_ptr_t buffer_;
    std::set<std::pair<service_t, method_t> > passengers_;

    std::chrono::nanoseconds minimal_debounce_time_;
    std::chrono::nanoseconds minimal_max_retention_time_;

    std::chrono::steady_clock::time_point departure_;
};


} // namespace vsomeip_v3

#endif // VSOMEIP_V3_BUFFER_HPP_
