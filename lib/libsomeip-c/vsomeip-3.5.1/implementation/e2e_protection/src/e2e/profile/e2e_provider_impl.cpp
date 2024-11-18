// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <sstream>

#include <vsomeip/internal/logger.hpp>

#include "../../../../e2e_protection/include/e2e/profile/e2e_provider_impl.hpp"

#include "../../../../e2e_protection/include/e2e/profile/profile01/checker.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile01/profile_01.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile01/protector.hpp"

#include "../../../../e2e_protection/include/e2e/profile/profile04/checker.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile04/profile_04.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile04/protector.hpp"

#include "../../../../e2e_protection/include/e2e/profile/profile05/checker.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile05/profile_05.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile05/protector.hpp"

#include "../../../../e2e_protection/include/e2e/profile/profile_custom/checker.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile_custom/profile_custom.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile_custom/protector.hpp"

#include "../../../../e2e_protection/include/e2e/profile/profile07/checker.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile07/profile_07.hpp"
#include "../../../../e2e_protection/include/e2e/profile/profile07/protector.hpp"

namespace {

template<typename value_t>
value_t read_value_from_config(const std::shared_ptr<vsomeip_v3::cfg::e2e> &_config,
                               const std::string &_name,
                               value_t _default_value = value_t()) {

    if (_config && _config->custom_parameters.count(_name)) {

        std::stringstream its_converter;
        std::string its_value(_config->custom_parameters[_name]);

        if (its_value.size() > 1 && its_value[0] == '0' && its_value[1] == 'x') {
            its_converter << std::hex << its_value;
        } else {
            its_converter << std::dec << its_value;
        }

        value_t its_converted_value;
        its_converter >> its_converted_value;
        return its_converted_value;
    }

    return _default_value;
}

} // namespace


VSOMEIP_PLUGIN(vsomeip_v3::e2e::e2e_provider_impl)

namespace vsomeip_v3 {
namespace e2e {

e2e_provider_impl::e2e_provider_impl()
    : plugin_impl("vsomeip e2e plugin", 1, plugin_type_e::APPLICATION_PLUGIN)
{
}

e2e_provider_impl::~e2e_provider_impl()
{
}

bool e2e_provider_impl::add_configuration(std::shared_ptr<cfg::e2e> config)
{
    if (config->profile == "CRC8" || config->profile == "P01") {
        process_e2e_profile<profile01::profile_config, profile01::profile_01_checker, profile01::protector>(config);
        return true;
    }

    if (config->profile == "CRC32" || config->profile == "CSTM") {
        process_e2e_profile<profile_custom::profile_config, profile_custom::profile_custom_checker, profile_custom::protector>(config);
        return true;
    }

    if (config->profile == "P04") {
        process_e2e_profile<profile04::profile_config, profile04::profile_04_checker, profile04::protector>(config);
        return true;
    }

    if (config->profile == "P05") {
        process_e2e_profile<profile05::profile_config, profile05::profile_05_checker, profile05::protector>(config);
        return true;
    }

    if (config->profile == "P07") {
        process_e2e_profile<profile07::profile_config, profile07::profile_07_checker, profile07::protector>(config);
        return true;
    }

    return false;
}

bool e2e_provider_impl::is_protected(e2exf::data_identifier_t id) const
{
    return custom_protectors_.count(id) > 0;
}

bool e2e_provider_impl::is_checked(e2exf::data_identifier_t id) const
{
    return custom_checkers_.count(id) > 0;
}

std::size_t e2e_provider_impl::get_protection_base(e2exf::data_identifier_t id) const
{
    const auto found_base = custom_bases_.find(id);
    if (found_base != custom_bases_.end())
        return found_base->second;

    return 0;
}

void e2e_provider_impl::protect(e2exf::data_identifier_t id, e2e_buffer &_buffer,
        instance_t _instance)
{
    auto protector = custom_protectors_.find(id);
    if(protector != custom_protectors_.end()) {
        protector->second->protect(_buffer, _instance);
    }
}

void e2e_provider_impl::check(e2exf::data_identifier_t id,
        const e2e_buffer &_buffer, instance_t _instance,
        profile_interface::check_status_t &_generic_check_status)
{
    auto checker = custom_checkers_.find(id);
    if(checker != custom_checkers_.end()) {
        checker->second->check(_buffer, _instance, _generic_check_status);
    }
}

template<>
vsomeip_v3::e2e::profile01::profile_config
e2e_provider_impl::make_e2e_profile_config(const std::shared_ptr<cfg::e2e> &_config) {
    uint16_t data_id = read_value_from_config<uint16_t>(_config, "data_id");
    uint16_t crc_offset = read_value_from_config<uint16_t>(_config, "crc_offset");
    uint16_t data_length = read_value_from_config<uint16_t>(_config, "data_length");

    // counter field behind CRC8
    uint16_t counter_offset = read_value_from_config<uint16_t>(_config, "counter_offset", 8);

    // data id nibble behind 4 bit counter value
    uint16_t data_id_nibble_offset = read_value_from_config<uint16_t>(_config, "data_id_nibble_offset", 12);

    e2e::profile01::p01_data_id_mode data_id_mode =
        static_cast<e2e::profile01::p01_data_id_mode>(
            read_value_from_config<uint16_t>(_config, "data_id_mode"));

    return e2e::profile01::profile_config(crc_offset, data_id, data_id_mode,
        data_length, counter_offset, data_id_nibble_offset);
}

template<>
vsomeip_v3::e2e::profile04::profile_config
e2e_provider_impl::make_e2e_profile_config(const std::shared_ptr<cfg::e2e> &_config) {

    uint32_t data_id = read_value_from_config<uint32_t>(_config, "data_id");

    size_t offset = read_value_from_config<size_t>(_config, "crc_offset");
    if (offset % 8)
        VSOMEIP_ERROR << "Offset in E2E P04 configuration must be multiple of 8"
            " (" << offset << ")";
    offset /= 8;

    size_t min_data_length = read_value_from_config<size_t>(_config,
            "min_data_length", 0);

    size_t max_data_length = read_value_from_config<size_t>(_config,
            "max_data_length", size_t(0xffff));

    uint16_t max_delta_counter = read_value_from_config<uint16_t>(_config,
            "max_delta_counter", uint16_t(0xffff));

    return e2e::profile04::profile_config(data_id, offset,
            min_data_length, max_data_length, max_delta_counter);
}

template<>
vsomeip_v3::e2e::profile05::profile_config
e2e_provider_impl::make_e2e_profile_config(const std::shared_ptr<cfg::e2e> &_config) {

    uint32_t data_id = read_value_from_config<uint32_t>(_config, "data_id");
    uint16_t data_length = read_value_from_config<uint16_t>(_config, "data_length");

    size_t offset = read_value_from_config<size_t>(_config, "crc_offset");
    if (offset % 8)
        VSOMEIP_ERROR << "Offset in E2E P05 configuration must be multiple of 8"
            " (" << offset << ")";
    offset /= 8;

    uint16_t max_delta_counter = read_value_from_config<uint16_t>(_config,
            "max_delta_counter", uint16_t(0xffff));

    return e2e::profile05::profile_config(data_id, data_length,
            offset, max_delta_counter);
}

template<>
e2e::profile_custom::profile_config
e2e_provider_impl::make_e2e_profile_config(const std::shared_ptr<cfg::e2e>& config) {
    uint16_t crc_offset = read_value_from_config<uint16_t>(config, "crc_offset");
    return e2e::profile_custom::profile_config(crc_offset);
}

template<>
vsomeip_v3::e2e::profile07::profile_config
e2e_provider_impl::make_e2e_profile_config(const std::shared_ptr<cfg::e2e> &_config) {

    uint32_t data_id = read_value_from_config<uint32_t>(_config, "data_id");

    size_t offset = read_value_from_config<size_t>(_config, "crc_offset");
    if (offset % 8)
        VSOMEIP_ERROR << "Offset in E2E P07 configuration must be multiple of 8"
            " (" << offset << ")";
    offset /= 8;

    size_t min_data_length = read_value_from_config<size_t>(_config,
            "min_data_length", 0);

    size_t max_data_length = read_value_from_config<size_t>(_config,
            "max_data_length", size_t(0xffffffff));

    uint32_t max_delta_counter = read_value_from_config<uint32_t>(_config,
            "max_delta_counter", uint32_t(0xffffffff));

    return e2e::profile07::profile_config(data_id, offset,
            min_data_length, max_data_length, max_delta_counter);
}

} // namespace e2e
} // namespace vsomeip_v3
