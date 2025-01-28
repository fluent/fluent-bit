// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/message_element_impl.hpp"

namespace vsomeip_v3 {
namespace sd {

message_element_impl::message_element_impl() {
    owner_ = 0;
}

message_impl * message_element_impl::get_owning_message() const {
    return owner_;
}

void message_element_impl::set_owning_message(message_impl *_owner) {
    owner_ = _owner;
}

} // namespace sd
} // namespace vsomeip_v3
