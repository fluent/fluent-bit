// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_POLICY_MANAGER_HPP_
#define VSOMEIP_V3_POLICY_MANAGER_HPP_


#include <memory>

#include <vsomeip/deprecated.hpp>
#include <vsomeip/export.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

struct policy;

class VSOMEIP_IMPORT_EXPORT policy_manager {
public:
    virtual ~policy_manager() {}
    virtual std::shared_ptr<policy> create_policy() const = 0;
    virtual void print_policy(const std::shared_ptr<policy> &_policy) const = 0;

    virtual bool parse_uid_gid(const byte_t* &_buffer, uint32_t &_buffer_size,
            uid_t &_uid, gid_t &_gid) const = 0;
    virtual bool parse_policy(const byte_t* &_buffer, uint32_t &_buffer_size,
            uid_t &_uid, gid_t &_gid,
            const std::shared_ptr<policy> &_policy) const = 0;

    virtual bool is_policy_update_allowed(uid_t _uid, std::shared_ptr<policy> &_policy) const = 0;
    virtual bool is_policy_removal_allowed(uid_t _uid) const = 0;
};

} // namespace vsomeip_v3


#endif // VSOMEIP_V3_POLICY_MANAGER_HPP_
