// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_POLICY_HPP_
#define VSOMEIP_V3_POLICY_HPP_

#include <cstring>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include <boost/icl/interval_map.hpp>
#include <boost/icl/interval_set.hpp>
#if defined(__QNX__)
#include <boost/icl/concept/interval_associator.hpp>
#endif

#include <vsomeip/constants.hpp>
#include <vsomeip/primitive_types.hpp>
#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

template<typename T_>
void get_bounds(const boost::icl::discrete_interval<T_> &_interval,
        T_ &_lower, T_ &_upper) {

    T_ its_lower, its_upper;

    its_lower = _interval.lower();
    its_upper = _interval.upper();

    switch (_interval.bounds().bits()) {
    case boost::icl::interval_bounds::static_open:
        its_lower++;
        its_upper--;
        break;
    case boost::icl::interval_bounds::static_left_open:
        its_lower++;
        break;
    case boost::icl::interval_bounds::static_right_open:
        its_upper--;
        break;
    default:
        ;
    }

    _lower = its_lower;
    _upper = its_upper;
}

struct policy {
    policy() : allow_who_(false), allow_what_(false) {};

    // Returns true if the policy is defined for single uid/gid pair.
    // uid & gid are copied to the arguments. Otherwise, returns false.
    bool get_uid_gid(uid_t &_uid, gid_t &_gid) const;

    bool deserialize_uid_gid(const byte_t * &_data, uint32_t &_size,
            uid_t &_uid, gid_t &_gid) const;
    bool deserialize(const byte_t * &_data, uint32_t &_size);
    bool serialize(std::vector<byte_t> &_data) const;

    void print() const;

    // Members
    boost::icl::interval_map<uid_t,
        boost::icl::interval_set<gid_t> > credentials_;
    bool allow_who_;

    boost::icl::interval_map<service_t,
        boost::icl::interval_map<instance_t,
            boost::icl::interval_set<method_t> > > requests_;
    boost::icl::interval_map<service_t,
        boost::icl::interval_set<instance_t> > offers_;
    bool allow_what_;

    mutable std::mutex mutex_;

private:
    bool deserialize_ids(const byte_t * &_data, uint32_t &_size,
            boost::icl::interval_map<uint16_t,
                boost::icl::interval_set<uint16_t> > &_ids) const;
    bool deserialize_id_item_list(const byte_t * &_data, uint32_t &_size,
            boost::icl::interval_set<uint16_t> &_intervals) const;
    bool deserialize_id_item(const byte_t * &_data, uint32_t &_size,
            uint16_t &_low, uint16_t &_high) const;

    bool deserialize_u32(const byte_t * &_data, uint32_t &_size,
            uint32_t &_value) const;
    bool deserialize_u16(const byte_t * &_data, uint32_t &_size,
            uint16_t &_value) const;

    bool serialize_uid_gid(std::vector<byte_t> &_data) const;
    void serialize_interval_set(
            const boost::icl::interval_set<uint16_t> &_intervals,
            std::vector<byte_t> &_data) const;
    void serialize_interval(
            const boost::icl::discrete_interval<uint16_t> &_interval,
            std::vector<byte_t> &_data) const;

    void serialize_u32(uint32_t _value, std::vector<byte_t> &_data) const;
    void serialize_u32_at(uint32_t _value, std::vector<byte_t> &_data,
            size_t _pos) const;
    void serialize_u16(uint16_t _value, std::vector<byte_t> &_data) const;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_POLICY_HPP_
