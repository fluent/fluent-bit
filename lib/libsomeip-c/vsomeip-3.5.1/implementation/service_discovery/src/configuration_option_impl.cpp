// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstring>

#include "../include/configuration_option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

configuration_option_impl::configuration_option_impl() {
    length_ = 2; // always contains "Reserved" and the trailing '\0'
    type_ = option_type_e::CONFIGURATION;
}

configuration_option_impl::~configuration_option_impl() {
}

bool
configuration_option_impl::equals(const option_impl &_other) const {
    bool is_equal(option_impl::equals(_other));

    if (is_equal) {
        const configuration_option_impl &its_other
            = dynamic_cast<const configuration_option_impl &>(_other);
        is_equal = (configuration_ == its_other.configuration_);
    }

    return is_equal;
}

void configuration_option_impl::add_item(const std::string &_key,
        const std::string &_value) {
    configuration_[_key] = _value;
    length_ = uint16_t(length_ + _key.length() + _value.length() + 2u); // +2 for the '=' and length
}

void configuration_option_impl::remove_item(const std::string &_key) {
    auto it = configuration_.find(_key);
    if (it != configuration_.end()) {
        length_ = uint16_t(length_ - (it->first.length() + it->second.length() + 2u));
        configuration_.erase(it);
    }
}

std::vector<std::string> configuration_option_impl::get_keys() const {
    std::vector < std::string > l_keys;
    for (const auto& elem : configuration_)
        l_keys.push_back(elem.first);
    return l_keys;
}

std::vector<std::string> configuration_option_impl::get_values() const {
    std::vector < std::string > l_values;
    for (const auto& elem : configuration_)
        l_values.push_back(elem.second);
    return l_values;
}

std::string configuration_option_impl::get_value(
        const std::string &_key) const {
    std::string l_value("");
    auto l_elem = configuration_.find(_key);
    if (l_elem != configuration_.end())
        l_value = l_elem->second;
    return l_value;
}

bool configuration_option_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful;
    std::string configuration_string;

    for (auto i = configuration_.begin(); i != configuration_.end(); ++i) {
        char l_length = char(1 + i->first.length() + i->second.length());
        configuration_string.push_back(l_length);
        configuration_string.append(i->first);
        configuration_string.push_back('=');
        configuration_string.append(i->second);
    }
    configuration_string.push_back('\0');

    is_successful = option_impl::serialize(_to);
    if (is_successful) {
        is_successful = _to->serialize(
                reinterpret_cast<const uint8_t*>(configuration_string.c_str()),
                uint32_t(configuration_string.length()));
    }

    return is_successful;
}

bool configuration_option_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful = option_impl::deserialize(_from);
    uint8_t l_itemLength = 0;
    std::string l_item(256, 0), l_key, l_value;

    do {
        l_itemLength = 0;
        l_key.clear();
        l_value.clear();
        l_item.assign(256, '\0');

        is_successful = is_successful && _from->deserialize(l_itemLength);
        if (l_itemLength > 0) {
            is_successful = is_successful
                    && _from->deserialize(l_item, static_cast<std::size_t>(l_itemLength));

            if (is_successful) {
                size_t l_eqPos = l_item.find('='); //SWS_SD_00292
                l_key = l_item.substr(0, l_eqPos);

                //if no "=" is found, no value is present for key (SWS_SD_00466)
                if( l_eqPos != std::string::npos )
                    l_value = l_item.substr(l_eqPos + 1);
                if (configuration_.end() == configuration_.find(l_key)) {
                    configuration_[l_key] = l_value;
                } else {
                    // TODO: log reason for failing deserialization
                    is_successful = false;
                }
            }
        } else {
              break;
        }
    } while (is_successful && _from->get_remaining() > 0);

    return is_successful;
}

} // namespace sd
} // namespace vsomeip_v3
