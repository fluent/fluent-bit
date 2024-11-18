// Copyright (C) 2020-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#if __GNUC__ > 11
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif

#include <iomanip>

#include <vsomeip/internal/logger.hpp>

#include "../include/policy.hpp"
#include "../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {

bool
policy::get_uid_gid(uid_t &_uid, gid_t &_gid) const {

    if (credentials_.size() != 1)
        return false;

    const auto its_uids = credentials_.begin()->first;
    const auto its_gids = credentials_.begin()->second;

    if (its_gids.size() != 1)
        return false;

    if (its_uids.lower() != its_uids.upper()
        || its_gids.begin()->lower() != its_gids.begin()->upper())
        return false;

    _uid = its_uids.lower();
    _gid = its_gids.begin()->lower();

    return true;
}

bool
policy::deserialize_uid_gid(const byte_t * &_data, uint32_t &_size,
            uid_t &_uid, gid_t &_gid) const {

    bool its_result;

    uint32_t raw_uid;
    its_result = deserialize_u32(_data, _size, raw_uid);
    if (its_result)
        _uid = static_cast<uid_t>(raw_uid);
    else
        return false;

    uint32_t raw_gid;
    its_result = deserialize_u32(_data, _size, raw_gid);
    if (its_result)
        _gid = static_cast<gid_t>(raw_gid);
    else
        return false;

    return true;
}

bool
policy::deserialize(const byte_t * &_data, uint32_t &_size) {

    bool its_result;
    uid_t its_uid;
    gid_t its_gid;

    std::lock_guard<std::mutex> its_lock(mutex_);

    its_result = deserialize_uid_gid(_data, _size, its_uid, its_gid);
    if (its_result == false)
        return false;

    // Fill policy uid/gid
    const auto its_uid_interval
        = boost::icl::interval<uid_t>::closed(its_uid, its_uid);
    boost::icl::interval_set<gid_t> its_gid_set;
    its_gid_set.insert(its_gid);
    credentials_ += std::make_pair(its_uid_interval, its_gid_set);

    // Deserialized policies are always "Allow" - policies
    allow_who_ = true;
    allow_what_ = true;

    // Deserialize requests array length
    uint32_t its_requests_length;
    its_result = deserialize_u32(_data, _size, its_requests_length);
    if (its_result == false)
        return false;

    // Deserialize requests
    while (0 < its_requests_length) {

        uint32_t its_current_size(_size);

        uint16_t its_service;
        its_result = deserialize_u16(_data, _size, its_service);
        if (its_result == false)
            return false;

        if (its_service == 0x0000 || its_service == 0xffff) {
            VSOMEIP_WARNING << "vSomeIP Security: Policy with service ID: 0x"
                    << std::hex << its_service << " is not allowed!";
            return false;
        }

        const auto its_service_interval
            = boost::icl::interval<service_t>::closed(its_service, its_service);

        boost::icl::interval_map<instance_t,
            boost::icl::interval_set<method_t> > its_ids;
        its_result = deserialize_ids(_data, _size, its_ids);
        if (its_result == false)
            return false;

        requests_ += std::make_pair(its_service_interval, its_ids);

        its_requests_length -= (its_current_size - _size);
    }

    // Deserialize offers array length
    uint32_t its_offers_length;
    its_result = deserialize_u32(_data, _size, its_offers_length);
    if (its_result == false)
        return false;

    while (0 < its_offers_length) {

        uint32_t its_current_size(_size);

        uint16_t its_service;
        its_result = deserialize_u16(_data, _size, its_service);
        if (its_result == false)
            return false;

        if (its_service == 0x0000 || its_service == 0xFFFF) {
            VSOMEIP_WARNING << "vSomeIP Security: Policy with service ID: 0x"
                    << std::hex << its_service << " is not allowed!";
            return false;
        }

        const auto its_service_interval
            = boost::icl::interval<service_t>::closed(its_service, its_service);

        boost::icl::interval_set<instance_t> its_instance_interval_set;
        its_result = deserialize_id_item_list(_data, _size,
                its_instance_interval_set);
        if (its_result == false)
            return false;

        offers_ += std::make_pair(its_service_interval, its_instance_interval_set);

        its_offers_length -= (its_current_size - _size);
    }

    return true;
}

bool
policy::deserialize_ids(const byte_t * &_data, uint32_t &_size,
        boost::icl::interval_map<uint16_t,
            boost::icl::interval_set<uint16_t> > &_ids) const {

    boost::icl::interval_map<uint16_t,
        boost::icl::interval_set<uint16_t> > its_ids;
    uint32_t its_array_length;
    bool its_result;

    its_result = deserialize_u32(_data, _size, its_array_length);
    if (its_result == false)
        return false;

    while (0 < its_array_length) {
        uint32_t its_current_size(_size);

        boost::icl::interval_set<uint16_t> its_instances, its_methods;
        its_result = deserialize_id_item_list(_data, _size, its_instances);
        if (its_result == false)
            return false;

        its_result = deserialize_id_item_list(_data, _size, its_methods);
        if (its_result == false)
            return false;

        for (const auto& i : its_instances)
            its_ids += std::make_pair(i, its_methods);

        its_array_length -= (its_current_size - _size);
    }

    _ids = std::move(its_ids);

    return true;
}

bool
policy::deserialize_id_item_list(const byte_t * &_data, uint32_t &_size,
        boost::icl::interval_set<uint16_t> &_intervals) const {

    boost::icl::interval_set<uint16_t> its_intervals;
    uint32_t its_length;
    bool its_result;

    its_result = deserialize_u32(_data, _size, its_length);
    if (its_result == false)
        return its_result;

    while (0 < its_length) {

        uint32_t its_current_size(_size);

        uint16_t its_low = 0;
        uint16_t its_high = 0;
        its_result = deserialize_id_item(_data, _size, its_low, its_high);
        if (its_result == false)
            return false;

        its_intervals.insert(boost::icl::interval<uint16_t>::closed(its_low, its_high));

        its_length -= (its_current_size - _size);
    }

    _intervals = std::move(its_intervals);

    return true;
}

bool
policy::deserialize_id_item(const byte_t * &_data, uint32_t &_size,
        uint16_t &_low, uint16_t &_high) const {

    uint32_t its_length, its_type;
    bool its_result;

    its_result = deserialize_u32(_data, _size, its_length);
    if (its_result == false)
        return false;

    its_result = deserialize_u32(_data, _size, its_type);
    if (its_result == false)
        return false;

    if (its_type == 1 && its_length == sizeof(uint16_t)) {
        its_result = deserialize_u16(_data, _size, _low);
        if (its_result == false)
            return false;

        _high = _low;
    } else if (its_type == 2
            && its_length == sizeof(uint16_t) + sizeof(uint16_t)) {
        its_result = deserialize_u16(_data, _size, _low);
        if (its_result == false)
            return false;

        its_result = deserialize_u16(_data, _size, _high);
        if (its_result == false)
            return false;

        if (_low > _high)
            return false;
    }

    // handle ANY_METHOD configuration
    if (_low == ANY_METHOD && _high == ANY_METHOD) {
        _low = 0x01;
    }

    return (_low != 0x0000);
}

bool
policy::deserialize_u16(const byte_t * &_data, uint32_t &_size,
        uint16_t &_value) const {

    if (_size < sizeof(uint16_t))
        return false;

    _value = bithelper::read_uint16_be(_data);

    _data += sizeof(uint16_t);
    _size -= static_cast<uint16_t>(sizeof(uint16_t));

    return true;
}

bool
policy::deserialize_u32(const byte_t * &_data, uint32_t &_size,
        uint32_t &_value) const {

    if (_size < sizeof(uint32_t))
        return false;

    _value = bithelper::read_uint32_be(_data);

    _data += sizeof(uint32_t);
    _size -= static_cast<uint32_t>(sizeof(uint32_t));

    return true;
}

bool
policy::serialize(std::vector<byte_t> &_data) const {

    bool its_result;

    std::lock_guard<std::mutex> its_lock(mutex_);

    its_result = serialize_uid_gid(_data);
    if (!its_result)
        return false;

    size_t its_requests_pos = _data.size();
    uint32_t its_requests_size(0);
    serialize_u32(its_requests_size, _data);

    for (const auto &its_request : requests_) {
        for (auto its_service = its_request.first.lower();
                its_service <= its_request.first.upper();
                its_service++) {

            serialize_u16(its_service, _data);

            size_t its_pos = _data.size();
            uint32_t its_instances_size(0);
            serialize_u32(its_instances_size, _data);

            for (const auto &i : its_request.second) {
                boost::icl::interval_set<instance_t> its_instances;
                its_instances.insert(i.first);
                serialize_interval_set(its_instances, _data);
                serialize_interval_set(i.second, _data);
            }

            its_instances_size = static_cast<uint32_t>(_data.size() - its_pos - sizeof(uint32_t));
            serialize_u32_at(its_instances_size, _data, its_pos);
        }
    }

    its_requests_size = static_cast<uint32_t>(_data.size() - its_requests_pos - sizeof(uint32_t));
    serialize_u32_at(its_requests_size, _data, its_requests_pos);

    uint32_t its_offers_size = 0;
    serialize_u32(its_offers_size, _data);

    return true;
}

bool
policy::serialize_uid_gid(std::vector<byte_t> &_data) const {

    if (credentials_.size() != 1) {
        VSOMEIP_ERROR << "Unserializable policy (ids).";
        return false;
    }

    auto its_credential = *(credentials_.begin());
    if (its_credential.second.size() != 1) {
        VSOMEIP_ERROR << "Unserializable policy (intervals).";
        return false;
    }

    auto its_uid_interval = its_credential.first;
    if (its_uid_interval.lower() != its_uid_interval.upper()) {
        VSOMEIP_ERROR << "Unserializable policy (uid).";
        return false;
    }

    auto its_gid_interval = *(its_credential.second.begin());
    if (its_gid_interval.lower() != its_gid_interval.upper()) {
        VSOMEIP_ERROR << "Unserializable policy (gid).";
        return false;
    }

    serialize_u32(its_uid_interval.lower(), _data);
    serialize_u32(its_gid_interval.lower(), _data);

    return true;
}

void
policy::serialize_interval_set(
        const boost::icl::interval_set<uint16_t> &_intervals,
        std::vector<byte_t> &_data) const {

    size_t its_pos(_data.size());
    uint32_t its_interval_set_size(0);
    serialize_u32(its_interval_set_size, _data);

    for (const auto& i : _intervals)
        serialize_interval(i, _data);

    its_interval_set_size = static_cast<uint32_t>(_data.size()
            - its_pos - sizeof(uint32_t));
    serialize_u32_at(its_interval_set_size, _data, its_pos);
}

void
policy::serialize_interval(
        const boost::icl::discrete_interval<uint16_t> &_interval,
        std::vector<byte_t> &_data) const {

    uint32_t its_union_length, its_union_type;

    if (_interval.lower() == _interval.upper()) { // single value
        its_union_length = static_cast<uint32_t>(sizeof(uint16_t));
        its_union_type = 1;

        serialize_u32(its_union_length, _data);
        serialize_u32(its_union_type, _data);

        serialize_u16(_interval.lower(), _data);
    } else { // value interval
        its_union_type = 2;
        its_union_length = static_cast<uint32_t>(
                sizeof(uint16_t) + sizeof(uint16_t));

        serialize_u32(its_union_length, _data);
        serialize_u32(its_union_type, _data);

        serialize_u16(_interval.lower(), _data);
        serialize_u16(_interval.upper(), _data);
    }
}

void
policy::serialize_u16(uint16_t _value,
        std::vector<byte_t> &_data) const {

    uint8_t new_buffer[2] = {0};
    bithelper::write_uint16_be(_value, new_buffer);
    _data.insert(_data.end(), new_buffer, new_buffer + sizeof(new_buffer));
}

void
policy::serialize_u32(uint32_t _value,
        std::vector<byte_t> &_data) const {

    uint8_t new_buffer[4] = {0};
    bithelper::write_uint32_be(_value, new_buffer);
    _data.insert(_data.end(), new_buffer, new_buffer + sizeof(new_buffer));
}

void
policy::serialize_u32_at(uint32_t _value,
        std::vector<byte_t> &_data, size_t _pos) const {

    bithelper::write_uint32_be(_value, &_data[_pos]);
}

void
policy::print() const {

    for (auto its_credential : credentials_) {
        auto its_uid_interval = its_credential.first;
        if (its_uid_interval.lower() == std::numeric_limits<uint32_t>::max()) {
            VSOMEIP_INFO << "policy::print Security configuration: UID: any";
        } else {
            VSOMEIP_INFO << "policy::print Security configuration: UID: "
                    << std::dec << its_uid_interval.lower();
        }
        for (auto its_gid_interval : its_credential.second) {
            if (its_gid_interval.lower() == std::numeric_limits<uint32_t>::max()) {
                VSOMEIP_INFO << "    policy::print Security configuration: GID: any";
            } else {
                VSOMEIP_INFO << "    policy::print Security configuration: GID: "
                        << std::dec << its_gid_interval.lower();
            }
        }
    }

    VSOMEIP_INFO << "policy::print Security configuration: REQUESTS POLICY SIZE: "
            << std::dec << requests_.size();
    for (auto its_request : requests_) {
        VSOMEIP_INFO << "policy::print ALLOWED REQUESTS Services:"
                << std::hex << its_request.first;
        for (auto its_instance : its_request.second) {
            VSOMEIP_INFO << "policy::print     Instances: ";
            VSOMEIP_INFO << "policy::print          first: 0x"
                    << std::hex << its_instance.first.lower()
                    << " last: 0x" << its_instance.first.upper();
            VSOMEIP_INFO << "policy::print     Methods: ";
            for (auto its_method : its_instance.second) {
                VSOMEIP_INFO << "policy::print          first: 0x"
                        << std::hex << its_method.lower()
                        << " last: 0x" << its_method.upper();
            }
        }
    }

    VSOMEIP_INFO << "policy::print Security configuration: OFFER POLICY SIZE: "
            << std::dec << offers_.size();
    for (auto its_offer : offers_) {
        VSOMEIP_INFO << "policy::print ALLOWED OFFERS Services:"
                << std::hex << its_offer.first;
        for (auto its_instance : its_offer.second) {
            VSOMEIP_INFO << "policy::print     Instances: ";
            VSOMEIP_INFO << "policy::print          first: 0x"
                        << std::hex << its_instance.lower()
                        << " last: 0x" << its_instance.upper();
        }
    }
}

} // namespace vsomeip_v3
