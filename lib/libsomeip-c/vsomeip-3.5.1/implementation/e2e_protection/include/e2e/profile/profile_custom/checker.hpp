// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE_CUSTOM_CHECKER_HPP
#define VSOMEIP_V3_E2E_PROFILE_CUSTOM_CHECKER_HPP

#include "../profile_custom/profile_custom.hpp"
#include "../profile_interface/checker.hpp"
#include <mutex>

namespace vsomeip_v3 {
namespace e2e {
namespace profile_custom {

class profile_custom_checker final
        : public e2e::profile_interface::checker {

public:
    profile_custom_checker(void) = delete;

    explicit profile_custom_checker(const e2e::profile_custom::profile_config &_config) :
            config_(_config) {}

    void check(const e2e_buffer &_buffer, instance_t _instance,
            e2e::profile_interface::check_status_t &_generic_check_status) override final;

private:
    uint32_t read_crc(const e2e_buffer &_buffer) const;

private:
    profile_config config_;
    std::mutex check_mutex_;

};

} // namespace profile_custom
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE_CUSTOM_CHECKER_HPP
