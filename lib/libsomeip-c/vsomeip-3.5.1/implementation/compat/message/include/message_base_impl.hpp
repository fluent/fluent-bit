// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_COMPAT_MESSAGE_BASE_IMPL_HPP_
#define VSOMEIP_COMPAT_MESSAGE_BASE_IMPL_HPP_

#include <compat/vsomeip/export.hpp>
#include <compat/vsomeip/message.hpp>
#include <vsomeip/message.hpp>

namespace vsomeip_v3 {
class message_impl;
} // namespace vsomeip_v3

namespace vsomeip {

class message;

class message_base_impl
        : virtual public message_base {

public:
    VSOMEIP_EXPORT message_base_impl(const std::shared_ptr<vsomeip_v3::message> &_impl);
    VSOMEIP_EXPORT virtual ~message_base_impl();

    VSOMEIP_EXPORT message_t get_message() const;
    VSOMEIP_EXPORT void set_message(message_t _message);

    VSOMEIP_EXPORT service_t get_service() const;
    VSOMEIP_EXPORT void set_service(service_t _service);

    VSOMEIP_EXPORT instance_t get_instance() const;
    VSOMEIP_EXPORT void set_instance(instance_t _instance);

    VSOMEIP_EXPORT method_t get_method() const;
    VSOMEIP_EXPORT void set_method(method_t _method);

    VSOMEIP_EXPORT length_t get_length() const;

    VSOMEIP_EXPORT request_t get_request() const;

    VSOMEIP_EXPORT client_t get_client() const;
    VSOMEIP_EXPORT void set_client(client_t _client);

    VSOMEIP_EXPORT session_t get_session() const;
    VSOMEIP_EXPORT void set_session(session_t _session);

    VSOMEIP_EXPORT protocol_version_t get_protocol_version() const;

    VSOMEIP_EXPORT interface_version_t get_interface_version() const;
    VSOMEIP_EXPORT void set_interface_version(interface_version_t _interface_version);

    VSOMEIP_EXPORT message_type_e get_message_type() const;
    VSOMEIP_EXPORT void set_message_type(message_type_e _type);

    VSOMEIP_EXPORT return_code_e get_return_code() const;
    VSOMEIP_EXPORT void set_return_code(return_code_e _code);

    VSOMEIP_EXPORT bool is_reliable() const;
    VSOMEIP_EXPORT void set_reliable(bool _is_reliable);

    VSOMEIP_EXPORT virtual bool is_initial() const;
    VSOMEIP_EXPORT virtual void set_initial(bool _is_initial);

    //VSOMEIP_EXPORT message * get_owner() const;
    //VSOMEIP_EXPORT void set_owner(message *_owner);

    VSOMEIP_EXPORT bool is_valid_crc() const;
    VSOMEIP_EXPORT void set_is_valid_crc(bool _is_valid_crc);

    inline std::shared_ptr<vsomeip_v3::message> get_impl() const { return impl_; }

protected:
    //message *owner_;
    std::shared_ptr<vsomeip_v3::message> impl_;
};

} // namespace vsomeip

#endif // VSOMEIP_COMPAT_MESSAGE_BASE_IMPL_HPP_
