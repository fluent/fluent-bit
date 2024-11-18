// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/defines.hpp>

#include "../include/message_base_impl.hpp"
#include "../include/message_header_impl.hpp"
#include "../include/serializer.hpp"
#include "../include/deserializer.hpp"

namespace vsomeip_v3 {

message_header_impl::message_header_impl()
    : service_(0x0), method_(0x0), length_(0x0),
      client_(0x0), session_(0x0),
      protocol_version_(0x1), interface_version_(0x0),
      type_(message_type_e::MT_UNKNOWN),
      code_(return_code_e::E_UNKNOWN),
      instance_(0x0), owner_(0x0) {
}

message_header_impl::message_header_impl(const message_header_impl &_header)
    : service_(_header.service_), method_(_header.method_),
      length_(_header.length_),
      client_(_header.client_), session_(_header.session_),
      protocol_version_(_header.protocol_version_),
      interface_version_(_header.interface_version_),
      type_(_header.type_),
      code_(_header.code_),
      instance_(_header.instance_), owner_(_header.owner_) {
}

bool message_header_impl::serialize(serializer *_to) const {
    return (0 != _to
            && _to->serialize(service_)
            && _to->serialize(method_)
            && _to->serialize(owner_->get_length())
            && _to->serialize(client_)
            && _to->serialize(session_)
            && _to->serialize(protocol_version_)
            && _to->serialize(interface_version_)
            && _to->serialize(static_cast<uint8_t>(type_))
            && _to->serialize(static_cast<uint8_t>(code_)));
}

bool message_header_impl::deserialize(deserializer *_from) {
    bool is_successful;

    uint8_t tmp_message_type, tmp_return_code;

    is_successful = (0 != _from
            && _from->deserialize(service_)
            && _from->deserialize(method_)
            && _from->deserialize(length_)
            && _from->deserialize(client_)
            && _from->deserialize(session_)
            && _from->deserialize(protocol_version_)
            && _from->deserialize(interface_version_)
            && _from->deserialize(tmp_message_type)
            && _from->deserialize(tmp_return_code));

    if (is_successful) {
        type_ = static_cast< message_type_e >(tmp_message_type);
        code_ = static_cast< return_code_e >(tmp_return_code);
    }

    return is_successful;
}

message_base * message_header_impl::get_owner() const {
    return owner_;
}

void message_header_impl::set_owner(message_base *_owner) {
    owner_ = _owner;
}

} // namespace vsomeip_v3
