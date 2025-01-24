// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_MESSAGE_ELEMENT_IMPL_HPP_
#define VSOMEIP_V3_SD_MESSAGE_ELEMENT_IMPL_HPP_

namespace vsomeip_v3 {
namespace sd {

class message_impl;

class message_element_impl {
public:
    message_element_impl();

    message_impl * get_owning_message() const;
    void set_owning_message(message_impl *_owner);

protected:
    message_impl *owner_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_MESSAGE_ELEMENT_IMPL_HPP_

