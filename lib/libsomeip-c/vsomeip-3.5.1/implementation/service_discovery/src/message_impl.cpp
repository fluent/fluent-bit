// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <typeinfo>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

// internal[_android.hpp] must be included before defines.hpp
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif // ANDROID

#include "../include/constants.hpp"
#include "../include/defines.hpp"
#include "../include/eventgroupentry_impl.hpp"
#include "../include/serviceentry_impl.hpp"
#include "../include/configuration_option_impl.hpp"
#include "../include/ipv4_option_impl.hpp"
#include "../include/ipv6_option_impl.hpp"
#include "../include/load_balancing_option_impl.hpp"
#include "../include/protection_option_impl.hpp"
#include "../include/selective_option_impl.hpp"
#include "../include/message_impl.hpp"
#include "../include/unknown_option_impl.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/payload_impl.hpp"
#include "../../message/include/serializer.hpp"

namespace vsomeip_v3 {
namespace sd {

message_impl::message_impl() :
    flags_(0x0),
    options_length_(0x0),
    current_message_size_(VSOMEIP_SOMEIP_SD_EMPTY_MESSAGE_SIZE) {
    header_.service_ = VSOMEIP_SD_SERVICE;
    header_.instance_ = VSOMEIP_SD_INSTANCE;
    header_.method_ = VSOMEIP_SD_METHOD;
    header_.client_ = VSOMEIP_SD_CLIENT;
    // session must be set dynamically
    header_.protocol_version_ = protocol_version;
    header_.interface_version_ = interface_version;
    header_.type_ = message_type;
    header_.code_ = return_code;

    set_unicast_flag(true);
}

message_impl::~message_impl() {
}

length_t message_impl::get_length() const {
    length_t current_length = VSOMEIP_SOMEIP_SD_DATA_SIZE;
    if( entries_.size()) {
        current_length += VSOMEIP_SOMEIP_SD_ENTRY_LENGTH_SIZE;
        current_length += uint32_t(entries_.size() * VSOMEIP_SOMEIP_SD_ENTRY_SIZE);
    }

    current_length += VSOMEIP_SOMEIP_SD_OPTION_LENGTH_SIZE;
    if(options_.size()) {
        for (size_t i = 0; i < options_.size(); ++i) {
            current_length += static_cast<length_t>(options_[i]->get_length()
                    + VSOMEIP_SOMEIP_SD_OPTION_HEADER_SIZE);
        }
    }
    return current_length;
}

length_t message_impl::get_size() const {
    return current_message_size_;
}

#define VSOMEIP_REBOOT_FLAG 0x80

bool message_impl::get_reboot_flag() const {
    return ((flags_ & VSOMEIP_REBOOT_FLAG) != 0);
}

void message_impl::set_reboot_flag(bool _is_set) {
    if (_is_set)
        flags_ |= flags_t(VSOMEIP_REBOOT_FLAG);
    else
        flags_ &= flags_t(~VSOMEIP_REBOOT_FLAG);
}

#define VSOMEIP_UNICAST_FLAG 0x40

bool message_impl::get_unicast_flag() const {
    return ((flags_ & VSOMEIP_UNICAST_FLAG) != 0);
}

void message_impl::set_unicast_flag(bool _is_set) {
    if (_is_set)
        flags_ |= flags_t(VSOMEIP_UNICAST_FLAG);
    else
        flags_ &= flags_t(~VSOMEIP_UNICAST_FLAG);
}

bool
message_impl::add_entry_data(const std::shared_ptr<entry_impl> &_entry,
        const std::vector<std::shared_ptr<option_impl> > &_options,
        const std::shared_ptr<entry_impl> &_other) {
    std::uint32_t its_entry_size = VSOMEIP_SOMEIP_SD_ENTRY_SIZE;
    std::map<const std::shared_ptr<option_impl>, bool> its_options;

    if (_other) {
        its_entry_size += VSOMEIP_SOMEIP_SD_ENTRY_SIZE;
    }

    // TODO: Check whether it is possible to express the options
    // by the two runs. If there are more than two options, it
    // might be necessary to copy an option, which then increases
    // the size...

    for (const std::shared_ptr<option_impl> &its_option : _options) {
        const auto its_existing_option = find_option(its_option);
        if (!its_existing_option) {
            its_entry_size += its_option->get_size();
            its_options[its_option] = true;
        } else {
            its_options[its_existing_option] = false;
        }
    }

    if (current_message_size_ + its_entry_size > VSOMEIP_MAX_UDP_SD_PAYLOAD)
        return false;

    entries_.push_back(_entry);
    _entry->set_owning_message(this);
    for (const auto &its_option : its_options) {
        if (its_option.second) {
            options_.push_back(its_option.first);
            its_option.first->set_owning_message(this);
        }
        _entry->assign_option(its_option.first);
    }

    if (_other) {
        entries_.push_back(_other);
        _other->set_owning_message(this);
        for (const auto &its_option : its_options) {
            _other->assign_option(its_option.first);
        }
    }

    current_message_size_ += its_entry_size;

    return true;
}

bool
message_impl::has_entry() const {
    return (0 < entries_.size());
}

bool
message_impl::has_option() const {
    return (0 < options_.size());
}

void message_impl::set_length(length_t _length) {
    (void)_length;
}

const message_impl::entries_t & message_impl::get_entries() const {
    return entries_;
}

const message_impl::options_t & message_impl::get_options() const {
    return options_;
}

std::shared_ptr<option_impl>
message_impl::find_option(const std::shared_ptr<option_impl> &_option) const {
    for (auto its_option : options_) {
        if (its_option->equals(*_option))
            return its_option;
    }
    return nullptr;
}

int16_t message_impl::get_option_index(
        const std::shared_ptr<option_impl> &_option) const {
    int16_t i = 0;

    while (i < int16_t(options_.size())) {
        if (options_[static_cast<options_t::size_type>(i)] == _option)
            return i;
        i++;
    }
    return -1;
}

std::shared_ptr<option_impl>
message_impl::get_option(int16_t _index) const {
    if (_index > -1) {
        size_t its_index = static_cast<size_t>(_index);
        if (its_index < options_.size())
            return options_[its_index];
    }
    return nullptr;
}

uint32_t message_impl::get_options_length() {
    return options_length_;
}

std::shared_ptr<payload> message_impl::get_payload() const {
    return std::make_shared<payload_impl>();
}

void message_impl::set_payload(std::shared_ptr<payload> _payload) {
    (void)_payload;
}

uint8_t message_impl::get_check_result() const {
    return 1;
}
void message_impl::set_check_result(uint8_t _check_result) {
    (void)_check_result;
}

bool message_impl::is_valid_crc() const {
    return false;
}

bool message_impl::serialize(vsomeip_v3::serializer *_to) const {
    bool is_successful = header_.serialize(_to);
    is_successful = is_successful && _to->serialize(flags_);
    is_successful = is_successful
            && _to->serialize(protocol::reserved_long, true);

    uint32_t entries_length = uint32_t(entries_.size() * VSOMEIP_SOMEIP_SD_ENTRY_SIZE);
    is_successful = is_successful && _to->serialize(entries_length);

    for (const auto& its_entry : entries_)
        is_successful = is_successful && its_entry && its_entry->serialize(_to);

    uint32_t options_length = 0;
    for (const auto& its_option : options_)
        options_length += its_option ? static_cast<uint32_t>(its_option->get_length()
                + VSOMEIP_SOMEIP_SD_OPTION_HEADER_SIZE) : 0;
    is_successful = is_successful && _to->serialize(options_length);

    for (const auto& its_option : options_)
        is_successful = is_successful && its_option && its_option->serialize(_to);

    return is_successful;
}

bool message_impl::deserialize(vsomeip_v3::deserializer *_from) {
    bool is_successful;
    bool option_is_successful(true);

    // header
    is_successful = header_.deserialize(_from);

    // flags
    is_successful = is_successful && _from->deserialize(flags_);

    // reserved
    uint32_t reserved;
    is_successful = is_successful && _from->deserialize(reserved, true);

    // entries
    uint32_t entries_length = 0;
    is_successful = is_successful && _from->deserialize(entries_length);

    // backup the current remaining length
    uint32_t save_remaining = uint32_t(_from->get_remaining());
    if (!is_successful) {
        // couldn't deserialize entries length
        return is_successful;
    } else if (entries_length > save_remaining) {
        // not enough data available to deserialize entries array
        is_successful = false;
        return is_successful;
    }

    // set remaining bytes to length of entries array
    _from->set_remaining(entries_length);

    // deserialize the entries
    while (is_successful && _from->get_remaining()) {
        std::shared_ptr < entry_impl > its_entry(deserialize_entry(_from));
        if (its_entry) {
            entries_.push_back(its_entry);
        } else {
            is_successful = false;
        }
    }

    // set length to remaining bytes after entries array
    _from->set_remaining(save_remaining - entries_length);

    // Don't try to deserialize options if there aren't any
    if(_from->get_remaining() == 0) {
        return is_successful;
    }

    // deserialize the options
    is_successful = is_successful && _from->deserialize(options_length_);

    // check if there is unreferenced data behind the last option and discard it
    if(_from->get_remaining() > options_length_) {
        _from->set_remaining(options_length_);
    }

    while (option_is_successful && _from->get_remaining()) {
        std::shared_ptr < option_impl > its_option(deserialize_option(_from));
        if (its_option) {
            options_.push_back(its_option);
        }  else {
            option_is_successful = false;
        }
    }
    current_message_size_ = 0;
    return is_successful;
}

entry_impl * message_impl::deserialize_entry(vsomeip_v3::deserializer *_from) {
    entry_impl *deserialized_entry = 0;
    uint8_t tmp_entry_type;

    if (_from->look_ahead(0, tmp_entry_type)) {
        entry_type_e deserialized_entry_type =
                static_cast<entry_type_e>(tmp_entry_type);

        switch (deserialized_entry_type) {
        case entry_type_e::FIND_SERVICE:
        case entry_type_e::OFFER_SERVICE:
            //case entry_type_e::STOP_OFFER_SERVICE:
        case entry_type_e::REQUEST_SERVICE:
            deserialized_entry = new serviceentry_impl;
            break;

        case entry_type_e::FIND_EVENT_GROUP:
        case entry_type_e::PUBLISH_EVENTGROUP:
            //case entry_type_e::STOP_PUBLISH_EVENTGROUP:
        case entry_type_e::SUBSCRIBE_EVENTGROUP:
            //case entry_type_e::STOP_SUBSCRIBE_EVENTGROUP:
        case entry_type_e::SUBSCRIBE_EVENTGROUP_ACK:
            //case entry_type_e::STOP_SUBSCRIBE_EVENTGROUP_ACK:
            deserialized_entry = new eventgroupentry_impl;
            break;

        default:
            break;
        };

        // deserialize object
        if (0 != deserialized_entry) {
            deserialized_entry->set_owning_message(this);
            if (!deserialized_entry->deserialize(_from)) {
                delete deserialized_entry;
                deserialized_entry = 0;
            };
        }
    }

    return deserialized_entry;
}

option_impl * message_impl::deserialize_option(vsomeip_v3::deserializer *_from) {
    option_impl *deserialized_option = 0;
    uint8_t tmp_option_type;

    if (_from->look_ahead(2, tmp_option_type)) {

        option_type_e deserialized_option_type =
                static_cast<option_type_e>(tmp_option_type);

        switch (deserialized_option_type) {

        case option_type_e::CONFIGURATION:
            deserialized_option = new configuration_option_impl;
            break;
        case option_type_e::LOAD_BALANCING:
            deserialized_option = new load_balancing_option_impl;
            break;
        case option_type_e::PROTECTION:
            deserialized_option = new protection_option_impl;
            break;
        case option_type_e::IP4_ENDPOINT:
        case option_type_e::IP4_MULTICAST:
            deserialized_option = new ipv4_option_impl;
            break;
        case option_type_e::IP6_ENDPOINT:
        case option_type_e::IP6_MULTICAST:
            deserialized_option = new ipv6_option_impl;
            break;
        case option_type_e::SELECTIVE:
            deserialized_option = new selective_option_impl;
            break;

        default:
            deserialized_option = new unknown_option_impl();
            break;
        };

        // deserialize object
        if (0 != deserialized_option
                && !deserialized_option->deserialize(_from)) {
            delete deserialized_option;
            deserialized_option = 0;
        };
    }

    return deserialized_option;
}

length_t message_impl::get_someip_length() const {
    return header_.length_;
}

uid_t message_impl::get_uid() const {
    return ANY_UID;
}

gid_t message_impl::get_gid() const {
    return ANY_GID;
}

vsomeip_sec_client_t message_impl::get_sec_client() const {
    static vsomeip_sec_client_t its_dummy_sec_client{
        ANY_UID, ANY_GID, 0, VSOMEIP_SEC_PORT_UNUSED
    };

    return its_dummy_sec_client;
}

std::string message_impl::get_env() const {
    return ("");
}

} // namespace sd
} // namespace vsomeip_v3
