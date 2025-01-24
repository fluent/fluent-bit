// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <algorithm>

#include <vsomeip/internal/logger.hpp>

#include "../include/entry_impl.hpp"
#include "../include/message_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

// TODO: throw exception if this constructor is used
entry_impl::entry_impl() {
    type_ = entry_type_e::UNKNOWN;
    major_version_ = 0;
    service_ = 0x0;
    instance_ = 0x0;
    ttl_ = 0x0;
    num_options_[0] = 0;
    num_options_[1] = 0;
    index1_ = 0;
    index2_ = 0;
}

entry_impl::entry_impl(const entry_impl &_entry) {
    type_ = _entry.type_;
    major_version_ = _entry.major_version_;
    service_ = _entry.service_;
    instance_ = _entry.instance_;
    ttl_ = _entry.ttl_;
    num_options_[0] = _entry.num_options_[0];
    num_options_[1] = _entry.num_options_[1];
    index1_ = _entry.index1_;
    index2_ = _entry.index2_;
}

entry_impl::~entry_impl() {
}

entry_type_e entry_impl::get_type() const {
    return type_;
}

void entry_impl::set_type(entry_type_e _type) {
    type_ = _type;
}

service_t entry_impl::get_service() const {
    return service_;
}

void entry_impl::set_service(service_t _service) {
    service_ = _service;
}

instance_t entry_impl::get_instance() const {
    return instance_;
}

void entry_impl::set_instance(instance_t _instance) {
    instance_ = _instance;
}

major_version_t entry_impl::get_major_version() const {
    return major_version_;
}

void entry_impl::set_major_version(major_version_t _major_version) {
    major_version_ = _major_version;
}

ttl_t entry_impl::get_ttl() const {
    return ttl_;
}

void entry_impl::set_ttl(ttl_t _ttl) {
    ttl_ = _ttl;
}

const std::vector<uint8_t> & entry_impl::get_options(uint8_t _run) const {
    static std::vector<uint8_t> invalid_options;
    if (_run > 0 && _run <= VSOMEIP_MAX_OPTION_RUN)
        return options_[_run - 1];

    return invalid_options;
}

void entry_impl::assign_option(const std::shared_ptr<option_impl> &_option) {
    int16_t i = get_owning_message()->get_option_index(_option);
    if (i > -1 && i < 256) {
        uint8_t its_index = static_cast<uint8_t>(i);
        if (options_[0].empty() ||
                options_[0][0] == its_index + 1 ||
                options_[0][options_[0].size() - 1] + 1 == its_index) {
            options_[0].push_back(its_index);
            std::sort(options_[0].begin(), options_[0].end());
            num_options_[0]++;
        } else if (options_[1].empty() ||
                options_[1][0] == its_index + 1 ||
                options_[1][options_[1].size() - 1] + 1 == its_index) {
            options_[1].push_back(its_index);
            std::sort(options_[1].begin(), options_[1].end());
            num_options_[1]++;
        } else {
            VSOMEIP_WARNING << "Option is not referenced by entries array, maximum number of endpoint options reached!";
        }
    } else {
        VSOMEIP_ERROR << "Option could not be found.";
    }
}

bool entry_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = (0 != _to
            && _to->serialize(static_cast<uint8_t>(type_)));

    uint8_t index_first_option_run = 0;
    if (options_[0].size() > 0)
        index_first_option_run = options_[0][0];
    is_successful = is_successful && _to->serialize(index_first_option_run);

    uint8_t index_second_option_run = 0;
    if (options_[1].size() > 0)
        index_second_option_run = options_[1][0];
    is_successful = is_successful && _to->serialize(index_second_option_run);

    uint8_t number_of_options = uint8_t((((uint8_t) options_[0].size()) << 4)
            | (((uint8_t) options_[1].size()) & 0x0F));
    is_successful = is_successful && _to->serialize(number_of_options);

    is_successful = is_successful
            && _to->serialize(static_cast<uint16_t>(service_));

    is_successful = is_successful
            && _to->serialize(static_cast<uint16_t>(instance_));

    return is_successful;
}

bool entry_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = (0 != _from);

    uint8_t its_type(0);
    is_successful = is_successful && _from->deserialize(its_type);
    type_ = static_cast<entry_type_e>(its_type);

    is_successful = is_successful && _from->deserialize(index1_);

    is_successful = is_successful && _from->deserialize(index2_);

    uint8_t its_numbers(0);
    is_successful = is_successful && _from->deserialize(its_numbers);

    num_options_[0] = uint8_t(its_numbers >> 4);
    num_options_[1] = uint8_t(its_numbers & 0xF);

    for (uint16_t i = index1_; i < index1_ + num_options_[0]; ++i)
        options_[0].push_back((uint8_t)(i));

    for (uint16_t i = index2_; i < index2_ + num_options_[1]; ++i)
        options_[1].push_back((uint8_t)(i));

    uint16_t its_id(0);
    is_successful = is_successful && _from->deserialize(its_id);
    service_ = static_cast<service_t>(its_id);

    is_successful = is_successful && _from->deserialize(its_id);
    instance_ = static_cast<instance_t>(its_id);

    return is_successful;
}

bool entry_impl::is_service_entry() const {
    return (type_ <= entry_type_e::REQUEST_SERVICE);
}

bool entry_impl::is_eventgroup_entry() const {
    return (type_ >= entry_type_e::FIND_EVENT_GROUP
            && type_ <= entry_type_e::SUBSCRIBE_EVENTGROUP_ACK);
}

uint8_t entry_impl::get_num_options(uint8_t _run) const {
    if (_run < 1 || _run > VSOMEIP_MAX_OPTION_RUN) {
        return 0x0;
    }
    return num_options_[_run-1];
}

} // namespace sd
} // namespace vsomeip_v3
