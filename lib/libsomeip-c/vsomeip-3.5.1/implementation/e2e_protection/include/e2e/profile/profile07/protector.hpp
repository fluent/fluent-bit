// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_PROFILE07_PROTECTOR_HPP
#define VSOMEIP_V3_E2E_PROFILE07_PROTECTOR_HPP

#include <map>
#include <mutex>

#include "../profile07/profile_07.hpp"
#include "../profile_interface/protector.hpp"

namespace vsomeip_v3 {
namespace e2e {
namespace profile07 {

class protector final : public e2e::profile_interface::protector {
public:
    protector(void) = delete;

    explicit protector(const profile_config &_config)
        : config_(_config) {}

    void protect(e2e_buffer &_buffer, instance_t _instance) override final;

private:
    bool verify_inputs(e2e_buffer &_buffer);
    uint32_t get_counter(instance_t _instance) const;
    void increment_counter(instance_t _instance);

    void write_32(e2e_buffer &_buffer, uint32_t _data, size_t _index);
    void write_64(e2e_buffer &_buffer, uint64_t _data, size_t _index);

private:
    profile_config config_;
    std::map<instance_t, uint32_t> counter_;
    std::mutex protect_mutex_;
};

} // namespace profile_07
} // namespace e2e
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_PROFILE07_PROTECTOR_HPP
