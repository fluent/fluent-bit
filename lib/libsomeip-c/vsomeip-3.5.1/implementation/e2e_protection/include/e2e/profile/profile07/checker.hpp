// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE07_CHECKER_HPP
#define VSOMEIP_V3_E2E_PROFILE07_CHECKER_HPP

#include <map>

#include "../profile07/profile_07.hpp"
#include "../profile_interface/checker.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile07 {

class profile_07_checker final : public e2e::profile_interface::checker {

public:
    profile_07_checker(void) = delete;

    // [SWS_E2E_00389] initialize state
    explicit profile_07_checker(const profile_config &_config) :
            config_(_config) {}

    void check(const e2e_buffer &_buffer, instance_t _instance,
            e2e::profile_interface::check_status_t &_generic_check_status) override final;

private:
    bool verify_input(const e2e_buffer &_buffer) const;
    bool verify_counter(instance_t _instance, uint32_t _received_counter);

    bool read_32(const e2e_buffer &_buffer, uint32_t &_data, size_t _index) const;
    bool read_64(const e2e_buffer &_buffer, uint64_t &_data, size_t _index) const;

    std::mutex check_mutex_;

    profile_config config_;
    std::map<instance_t, uint32_t> counter_;
};

} // namespace profile_07
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE07_CHECKER_HPP
