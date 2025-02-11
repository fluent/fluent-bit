// Copyright (C) 2017-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TRACE_CHANNEL_IMPL_HPP_
#define VSOMEIP_V3_TRACE_CHANNEL_IMPL_HPP_

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>

#include "enumeration_types.hpp"
#include <vsomeip/trace.hpp>

namespace vsomeip_v3 {
namespace trace {

typedef std::function<bool (service_t, instance_t, method_t)> filter_func_t;

class channel_impl : public channel {
public:
    channel_impl(const std::string &_id, const std::string &_name);

    std::string get_id() const;
    std::string get_name() const;

    filter_id_t add_filter(
            const match_t &_match,
            filter_type_e _type);

    filter_id_t add_filter(
            const match_t &_match,
            bool _is_positive);

    filter_id_t add_filter(
            const std::vector<match_t> &_matches,
            bool _is_positive);

    filter_id_t add_filter(
            const std::vector<match_t> &_matches,
            filter_type_e _type);

    filter_id_t add_filter(
            const match_t &_from, const match_t &_to,
            bool _is_positive);

    filter_id_t add_filter(
            const match_t &_from, const match_t &_to,
            filter_type_e _type);

    void remove_filter(
            filter_id_t _id);

    std::pair<bool, bool> matches(service_t _service, instance_t _instance, method_t _method);

private:
    filter_id_t add_filter_intern(const filter_func_t& _func, filter_type_e _type);

    std::string id_;
    std::string name_;

    std::atomic<filter_id_t> current_filter_id_;

    std::map<filter_id_t, std::pair<filter_func_t, bool>> positive_;
    std::map<filter_id_t, filter_func_t> negative_;
    std::mutex mutex_; // protects positive_ & negative_
};

} // namespace trace
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TRACE_CHANNEL_IMPL_HPP_
