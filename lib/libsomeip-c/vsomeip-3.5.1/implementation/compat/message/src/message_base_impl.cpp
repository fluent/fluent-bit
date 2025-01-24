// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/runtime.hpp>

#include "../include/message_base_impl.hpp"
#include "../../../message/include/message_impl.hpp"

namespace vsomeip {

message_base_impl::message_base_impl(
        const std::shared_ptr<vsomeip_v3::message> &_impl)
    : impl_(_impl) {
}

message_base_impl::~message_base_impl() {
}

message_t
message_base_impl::get_message() const {
    return impl_->get_message();
}

void
message_base_impl::set_message(message_t _message) {
    impl_->set_message(_message);
}

service_t
message_base_impl::get_service() const {
    return impl_->get_service();
}

void
message_base_impl::set_service(service_t _service) {
    impl_->set_service(_service);
}

instance_t
message_base_impl::get_instance() const {
    return impl_->get_instance();
}

void
message_base_impl::set_instance(instance_t _instance) {
    impl_->set_instance(_instance);
}

method_t
message_base_impl::get_method() const {
    return impl_->get_method();
}

void
message_base_impl::set_method(method_t _method) {
    impl_->set_method(_method);
}

length_t
message_base_impl::get_length() const {
    return impl_->get_length();
}

request_t
message_base_impl::get_request() const {
    return impl_->get_request();
}

client_t
message_base_impl::get_client() const {
    return impl_->get_client();
}

void
message_base_impl::set_client(client_t _client) {
    impl_->set_client(_client);
}

session_t
message_base_impl::get_session() const {
    return impl_->get_session();
}

void
message_base_impl::set_session(session_t _session) {
    impl_->set_session(_session);
}

protocol_version_t
message_base_impl::get_protocol_version() const {
    return impl_->get_protocol_version();
}

interface_version_t
message_base_impl::get_interface_version() const {
    return impl_->get_interface_version();
}

void
message_base_impl::set_interface_version(interface_version_t _interface_version) {
    impl_->set_interface_version(_interface_version);
}

message_type_e
message_base_impl::get_message_type() const {
    return static_cast<message_type_e>(impl_->get_message_type());
}

void
message_base_impl::set_message_type(message_type_e _type) {
    impl_->set_message_type(static_cast<vsomeip_v3::message_type_e>(_type));
}

return_code_e
message_base_impl::get_return_code() const {
    return static_cast<return_code_e>(impl_->get_return_code());
}

void
message_base_impl::set_return_code(return_code_e _code) {
    impl_->set_return_code(static_cast<vsomeip_v3::return_code_e>(_code));
}

bool
message_base_impl::is_reliable() const {
    return impl_->is_reliable();
}

void
message_base_impl::set_reliable(bool _is_reliable) {
    impl_->set_reliable(_is_reliable);
}

bool
message_base_impl::is_initial() const {
    return impl_->is_initial();
}

void
message_base_impl::set_initial(bool _is_initial) {
    impl_->set_initial(_is_initial);
}
/*
message *
message_base_impl::get_owner() const {
    return owner_;
}

void
message_base_impl::set_owner(message *_owner) {
    owner_ = _owner;
}
*/
bool
message_base_impl::is_valid_crc() const {
    return impl_->is_valid_crc();
}

void
message_base_impl::set_is_valid_crc(bool _is_valid_crc) {
    impl_->set_check_result(_is_valid_crc == true ? 1 : 0);
}

} // namespace vsomeip
