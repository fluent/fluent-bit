// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_MESSAGE_IMPL_HPP_
#define VSOMEIP_V3_SD_MESSAGE_IMPL_HPP_

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

#include <vsomeip/message.hpp>

#include "../include/primitive_types.hpp"
#include "../../message/include/message_base_impl.hpp"
#include "../../endpoints/include/endpoint_definition.hpp"

#  if _MSC_VER >= 1300
/*
* Diamond inheritance is used for the vsomeip::message_base base class.
* The Microsoft compiler put warning (C4250) using a desired c++ feature: "Delegating to a sister class"
* A powerful technique that arises from using virtual inheritance is to delegate a method from a class in another class
* by using a common abstract base class. This is also called cross delegation.
*/
#    pragma warning( disable : 4250 )
#  endif

namespace vsomeip_v3 {
namespace sd {

class entry_impl;
class eventgroupentry_impl;
class serviceentry_impl;

class option_impl;
class configuration_option_impl;
class load_balancing_option_impl;
class protection_option_impl;
class selective_option_impl;

class message_impl
        : public vsomeip_v3::message, public vsomeip_v3::message_base_impl {
public:
    typedef std::vector<std::shared_ptr<entry_impl>> entries_t;
    typedef std::vector<std::shared_ptr<option_impl>> options_t;
    struct forced_initial_events_t {
        std::shared_ptr<vsomeip_v3::endpoint_definition> target_;
        vsomeip_v3::service_t service_;
        vsomeip_v3::instance_t instance_;
        vsomeip_v3::eventgroup_t eventgroup_;
    };
    message_impl();
    virtual ~message_impl();

    length_t get_length() const;
    void set_length(length_t _length);

    length_t get_size() const;

    bool get_reboot_flag() const;
    void set_reboot_flag(bool _is_set);

    bool get_unicast_flag() const;
    void set_unicast_flag(bool _is_set);

    bool has_entry() const;
    bool has_option() const;

    const entries_t & get_entries() const;
    const options_t & get_options() const;

    bool add_entry_data(const std::shared_ptr<entry_impl> &_entry,
            const std::vector<std::shared_ptr<option_impl> > &_options,
            const std::shared_ptr<entry_impl> &_other = nullptr);

    std::shared_ptr<option_impl> find_option(
            const std::shared_ptr<option_impl> &_option) const;

    int16_t get_option_index(const std::shared_ptr<option_impl> &_option) const;
    std::shared_ptr<option_impl> get_option(int16_t _index) const;
    uint32_t get_options_length();

    std::shared_ptr<payload> get_payload() const;
    void set_payload(std::shared_ptr<payload> _payload);

    uint8_t get_check_result() const;
    void set_check_result(uint8_t _check_result);
    bool is_valid_crc() const;

    bool serialize(vsomeip_v3::serializer *_to) const;
    bool deserialize(vsomeip_v3::deserializer *_from);

    length_t get_someip_length() const;

    void forced_initial_events_add(forced_initial_events_t _entry);
    const std::vector<forced_initial_events_t> forced_initial_events_get();

    void set_initial_events_required(bool _initial_events_required);
    bool initial_events_required() const;

    uid_t get_uid() const;
    gid_t get_gid() const;
    vsomeip_sec_client_t get_sec_client() const;
    std::string get_env() const;

private:
    entry_impl * deserialize_entry(vsomeip_v3::deserializer *_from);
    option_impl * deserialize_option(vsomeip_v3::deserializer *_from);

private:
    flags_t flags_;
    uint32_t options_length_;

    entries_t entries_;
    options_t options_;

    std::mutex message_mutex_;

    std::uint32_t current_message_size_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_MESSAGE_IMPL_HPP_
