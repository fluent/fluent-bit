// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/defines.hpp>
#include <vsomeip/payload.hpp>
#include <vsomeip/runtime.hpp>

#include "../include/message_impl.hpp"
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif

namespace vsomeip_v3 {

message_impl::message_impl()
    : payload_(runtime::get()->create_payload()),
      check_result_ {0},
      sec_client_ {ANY_UID, ANY_GID, 0, VSOMEIP_SEC_PORT_UNUSED} {
}

message_impl::~message_impl() {
}

length_t message_impl::get_length() const {
    return (VSOMEIP_SOMEIP_HEADER_SIZE
            + (payload_ ? payload_->get_length() : 0));
}

std::shared_ptr< payload > message_impl::get_payload() const {
    return payload_;
}

void message_impl::set_payload(std::shared_ptr< payload > _payload) {
    payload_ = _payload;
}

bool message_impl::serialize(serializer *_to) const {
    return (header_.serialize(_to)
            && (payload_ ? payload_->serialize(_to) : true));
}

bool message_impl::deserialize(deserializer *_from) {
    payload_ = runtime::get()->create_payload();
    bool is_successful = header_.deserialize(_from);
    if (is_successful) {
        payload_->set_capacity(header_.length_ - VSOMEIP_SOMEIP_HEADER_SIZE);
        is_successful = payload_->deserialize(_from);
    }
    return is_successful;
}

uint8_t message_impl::get_check_result() const {
    return check_result_;
}

void message_impl::set_check_result(uint8_t _check_result) {
    check_result_ = _check_result;
}

bool message_impl::is_valid_crc() const {
    return (check_result_ == 0);
}

uid_t message_impl::get_uid() const {

    return sec_client_.user;
}

gid_t message_impl::get_gid() const {

    return sec_client_.group;
}

vsomeip_sec_client_t message_impl::get_sec_client() const {

    return sec_client_;
}

void message_impl::set_sec_client(const vsomeip_sec_client_t &_sec_client) {

    sec_client_ = _sec_client;
}

std::string message_impl::get_env() const {
    return env_;
}

void message_impl::set_env(const std::string &_env) {
    env_ = _env;
}

} // namespace vsomeip_v3
