// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_STRUCTURED_TYPES_HPP_
#define VSOMEIP_V3_STRUCTURED_TYPES_HPP_

#include <chrono>
#include <map>

namespace vsomeip_v3 {

// Messages are forwarded either because their value differs from the
// last received message (on_change) or because the specified time
// (interval) between two messages has elapsed. A message that is forwarded
// because of a changed value may reset the time until the next unchanged
// message is forwarded or not (on_change_resets_interval). By specifiying
// indexes and bit masks, the comparison that is carried out to decide whether
// or not two message values differ is configurable (ignore).
struct debounce_filter_t {
    debounce_filter_t()
        : on_change_(false),
          on_change_resets_interval_(false),
          interval_(-1),
          send_current_value_after_(false) {
    }

    debounce_filter_t(const debounce_filter_t &_source)
        : on_change_(_source.on_change_),
          on_change_resets_interval_(_source.on_change_resets_interval_),
          interval_(_source.interval_),
          ignore_(_source.ignore_),
          send_current_value_after_(_source.send_current_value_after_) {
    }

    inline void operator=(const debounce_filter_t &_other) {
        on_change_ = _other.on_change_;
        on_change_resets_interval_ = _other.on_change_resets_interval_;
        interval_ = _other.interval_;
        ignore_ = _other.ignore_;
        send_current_value_after_ = _other.send_current_value_after_;
    }

    inline bool operator==(const debounce_filter_t &_other) const {

        return (on_change_ == _other.on_change_
                && on_change_resets_interval_ == _other.on_change_resets_interval_
                && interval_ == _other.interval_
                && ignore_ == _other.ignore_
                && send_current_value_after_ == _other.send_current_value_after_);
    }

    inline bool operator!=(const debounce_filter_t &_other) const {

        return (on_change_ != _other.on_change_
                || on_change_resets_interval_ != _other.on_change_resets_interval_
                || interval_ != _other.interval_
                || ignore_ != _other.ignore_
                || send_current_value_after_ != _other.send_current_value_after_);
    }

    bool on_change_;
    bool on_change_resets_interval_;
    int64_t interval_;
    std::map<std::size_t, byte_t> ignore_;
    bool send_current_value_after_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_STRUCTURED_TYPES_HPP
