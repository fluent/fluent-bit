// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/message_impl.hpp"
#include "../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {

message_base_impl::message_base_impl()
    : is_reliable_(false),
      is_initial_(false) {
    header_.set_owner(this);
}

message_base_impl::~message_base_impl() {
}

// header interface
message_t message_base_impl::get_message() const {
    const uint8_t header_message[] = {static_cast<uint8_t>((header_.service_ & 0xFF00) >> 8),
                                      static_cast<uint8_t>( header_.service_ & 0x00FF),
                                      static_cast<uint8_t>((header_.method_  & 0xFF00) >> 8),
                                      static_cast<uint8_t>( header_.method_  & 0x00FF)};
    return bithelper::read_uint32_be(header_message);
}

void message_base_impl::set_message(message_t _message) {
    header_.service_ = bithelper::read_high_word(_message);
    header_.method_  = bithelper::read_low_word(_message);
}

service_t message_base_impl::get_service() const {
    return header_.service_;
}

void message_base_impl::set_service(service_t _service) {
    header_.service_ = _service;
}

instance_t message_base_impl::get_instance() const {
    return header_.instance_;
}

void message_base_impl::set_instance(instance_t _instance) {
    header_.instance_ = _instance;
}

method_t message_base_impl::get_method() const {
    return header_.method_;
}

void message_base_impl::set_method(method_t _method) {
    header_.method_ = _method;
}

request_t message_base_impl::get_request() const {
    const uint8_t header_message[] = {static_cast<uint8_t>((header_.client_  & 0xFF00) >> 8),
                                      static_cast<uint8_t>( header_.client_  & 0x00FF),
                                      static_cast<uint8_t>((header_.session_ & 0xFF00) >> 8),
                                      static_cast<uint8_t>( header_.session_ & 0x00FF)};
    return bithelper::read_uint32_be(header_message);
}

client_t message_base_impl::get_client() const {
    return header_.client_;
}

void message_base_impl::set_client(client_t _client) {
    header_.client_ = _client;
}

session_t message_base_impl::get_session() const {
    return header_.session_;
}

void message_base_impl::set_session(session_t _session) {
    header_.session_ = _session;
}

protocol_version_t message_base_impl::get_protocol_version() const {
    return header_.protocol_version_;
}

void message_base_impl::set_protocol_version(protocol_version_t _protocol_version) {
    header_.protocol_version_ = _protocol_version;
}

interface_version_t message_base_impl::get_interface_version() const {
    return header_.interface_version_;
}

void message_base_impl::set_interface_version(interface_version_t _interface_version) {
    header_.interface_version_ = _interface_version;
}

message_type_e message_base_impl::get_message_type() const {
    return header_.type_;
}

void message_base_impl::set_message_type(message_type_e _type) {
    header_.type_ = _type;
}

return_code_e message_base_impl::get_return_code() const {
    return header_.code_;
}

void message_base_impl::set_return_code(return_code_e _code) {
    header_.code_ = _code;
}

bool message_base_impl::is_reliable() const {
    return is_reliable_;
}

void message_base_impl::set_reliable(bool _is_reliable) {
    is_reliable_ = _is_reliable;
}

bool message_base_impl::is_initial() const {
    return is_initial_;
}

void message_base_impl::set_initial(bool _is_initial) {
    is_initial_ = _is_initial;
}

} // namespace vsomeip_v3
