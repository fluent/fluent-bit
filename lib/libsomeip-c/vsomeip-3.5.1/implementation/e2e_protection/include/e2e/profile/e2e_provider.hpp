// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROVIDER_HPP
#define VSOMEIP_V3_E2E_PROVIDER_HPP

#include <string>
#include <memory>

#include "../../buffer/buffer.hpp"
#include "../../e2exf/config.hpp"
#include "../../../../configuration/include/e2e.hpp"
#include "profile_interface/profile_interface.hpp"

namespace vsomeip_v3 {
namespace e2e {

class e2e_provider {
public:
    virtual bool add_configuration(std::shared_ptr<cfg::e2e> config) = 0;

    virtual bool is_protected(e2exf::data_identifier_t id) const = 0;
    virtual bool is_checked(e2exf::data_identifier_t id) const = 0;

    virtual std::size_t get_protection_base(e2exf::data_identifier_t _id) const = 0;

    virtual void protect(e2exf::data_identifier_t id,
            e2e_buffer &_buffer, instance_t _instance) = 0;
    virtual void check(e2exf::data_identifier_t id,
            const e2e_buffer &_buffer, instance_t _instance,
            e2e::profile_interface::check_status_t &_generic_check_status) = 0;
};

} // namespace e2e
} // namespace vsomeip_v3

#endif  // VSOMEIP_V3_E2E_PROVIDER_HPP
