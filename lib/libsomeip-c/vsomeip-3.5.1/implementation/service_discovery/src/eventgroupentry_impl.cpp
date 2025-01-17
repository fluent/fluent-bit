// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/internal/logger.hpp>

#include "../include/constants.hpp"
#include "../include/eventgroupentry_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"
#include "../include/ipv4_option_impl.hpp"
#include "../include/ipv6_option_impl.hpp"
#include "../include/selective_option_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

eventgroupentry_impl::eventgroupentry_impl() :
    reserved_(0) {
    eventgroup_ = 0xFFFF;
    counter_ = 0;
}

eventgroupentry_impl::eventgroupentry_impl(const eventgroupentry_impl &_entry)
        : entry_impl(_entry),
          reserved_(0) {
    eventgroup_ = _entry.eventgroup_;
    counter_ = _entry.counter_;
}

eventgroupentry_impl::~eventgroupentry_impl() {
}

eventgroup_t eventgroupentry_impl::get_eventgroup() const {
    return eventgroup_;
}

void eventgroupentry_impl::set_eventgroup(eventgroup_t _eventgroup) {
    eventgroup_ = _eventgroup;
}

uint16_t eventgroupentry_impl::get_reserved() const {
    return reserved_;
}

void eventgroupentry_impl::set_reserved(uint16_t _reserved) {
    reserved_ = _reserved;
}

uint8_t eventgroupentry_impl::get_counter() const {
    return counter_;
}

void eventgroupentry_impl::set_counter(uint8_t _counter) {
    counter_ = _counter;
}

bool eventgroupentry_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = entry_impl::serialize(_to);
    is_successful = is_successful && _to->serialize(major_version_);
    is_successful = is_successful
            && _to->serialize(static_cast<uint32_t>(ttl_), true);
    is_successful = is_successful
            && _to->serialize(protocol::reserved_word);
    is_successful = is_successful
            && _to->serialize(static_cast<uint16_t>(eventgroup_));

    return is_successful;
}

bool eventgroupentry_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = entry_impl::deserialize(_from);

    uint8_t tmp_major_version(0);
    is_successful = is_successful && _from->deserialize(tmp_major_version);
    major_version_ = static_cast<major_version_t>(tmp_major_version);

    uint32_t its_ttl(0);
    is_successful = is_successful && _from->deserialize(its_ttl, true);
    ttl_ = static_cast<ttl_t>(its_ttl);

    is_successful = is_successful && _from->deserialize(reserved_);

    uint16_t its_eventgroup = 0;
    is_successful = is_successful && _from->deserialize(its_eventgroup);
    eventgroup_ = static_cast<eventgroup_t>(its_eventgroup);

    return is_successful;
}

bool eventgroupentry_impl::matches(const eventgroupentry_impl& _other,
        const message_impl::options_t& _options) const {
    if (service_ == _other.service_
            && instance_ == _other.instance_
            && eventgroup_ == _other.eventgroup_
            && major_version_ == _other.major_version_
            && counter_ == _other.counter_) {

        // Check, whether options are identical
        if (index1_ == _other.index1_
            && index2_ == _other.index2_
            && num_options_[0] == _other.num_options_[0]
            && num_options_[1] == _other.num_options_[1]) {
            return true;
        }

        // check if entries reference options at different indexes but the
        // options itself are identical
        // check if number of options referenced is the same
        if (num_options_[0] + num_options_[1]
                != _other.num_options_[0] + _other.num_options_[1] ||
                num_options_[0] + num_options_[1] == 0) {
            return false;
        }

        // read out ip options of current and _other
        std::vector<std::shared_ptr<ip_option_impl>> its_options_current;
        std::vector<std::shared_ptr<ip_option_impl>> its_options_other;
        const std::size_t its_options_size = _options.size();
        for (const auto option_run : {0,1}) {
            for (const auto option_index : options_[option_run]) {
                if (its_options_size > option_index) {
                    switch (_options[option_index]->get_type()) {
                        case option_type_e::IP4_ENDPOINT:
                            its_options_current.push_back(
                                    std::static_pointer_cast<ipv4_option_impl>(
                                            _options[option_index]));
                            break;
                        case option_type_e::IP6_ENDPOINT:
                            its_options_current.push_back(
                                    std::static_pointer_cast<ipv6_option_impl>(
                                            _options[option_index]));
                            break;
                        default:
                            break;
                    }
                }
            }
            for (const auto option_index : _other.options_[option_run]) {
                if (its_options_size > option_index) {
                    switch (_options[option_index]->get_type()) {
                        case option_type_e::IP4_ENDPOINT:
                            its_options_other.push_back(
                                    std::static_pointer_cast<ipv4_option_impl>(
                                            _options[option_index]));
                            break;
                        case option_type_e::IP6_ENDPOINT:
                            its_options_other.push_back(
                                    std::static_pointer_cast<ipv6_option_impl>(
                                            _options[option_index]));
                            break;
                        default:
                            break;
                    }
                }
            }
        }

        if (!its_options_current.size() || !its_options_other.size()) {
            return false;
        }

        // search every option of current in other
        for (const auto& c : its_options_current) {
            bool found(false);
            for (const auto& o : its_options_other) {
                if (c->equals(*o)) {
                    switch (c->get_type()) {
                        case option_type_e::IP4_ENDPOINT:
                            if (static_cast<ipv4_option_impl*>(c.get())->get_address()
                                    == static_cast<ipv4_option_impl*>(o.get())->get_address()) {
                                found = true;
                            }
                            break;
                        case option_type_e::IP6_ENDPOINT:
                            if (static_cast<ipv6_option_impl*>(c.get())->get_address()
                                    == static_cast<ipv6_option_impl*>(o.get())->get_address()) {
                                found = true;
                            }
                            break;
                        default:
                            break;
                    }
                }
                if (found) {
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }
    return false;
}

void eventgroupentry_impl::add_target(
        const std::shared_ptr<endpoint_definition> &_target) {
    if (_target->is_reliable()) {
        target_reliable_ = _target;
    } else {
        target_unreliable_ = _target;
    }
}

std::shared_ptr<endpoint_definition> eventgroupentry_impl::get_target(
        bool _reliable) const {
    return _reliable ? target_reliable_ : target_unreliable_;
}

std::shared_ptr<selective_option_impl>
eventgroupentry_impl::get_selective_option() const {
    for (const auto i : {0, 1}) {
        for (const auto j : options_[i]) {
            auto its_option = std::dynamic_pointer_cast<
                    selective_option_impl>(owner_->get_option(j));
            if (its_option)
                return its_option;
        }
    }
    return nullptr;
}

} // namespace sd
} // namespace vsomeip_v3
