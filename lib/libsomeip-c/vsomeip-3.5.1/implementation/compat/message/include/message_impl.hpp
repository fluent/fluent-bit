// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_COMPAT_MESSAGE_IMPL_HPP_
#define VSOMEIP_COMPAT_MESSAGE_IMPL_HPP_

#if _MSC_VER >= 1300
#    pragma warning( disable : 4250 )
#endif

#include <compat/vsomeip/message.hpp>
#include "message_base_impl.hpp"

namespace vsomeip {

class payload;

class message_impl
        : virtual public message_base_impl,
          virtual public message {

public:
    VSOMEIP_EXPORT message_impl(const std::shared_ptr<vsomeip_v3::message> &_impl);
    VSOMEIP_EXPORT virtual ~message_impl();

    VSOMEIP_EXPORT std::shared_ptr< payload > get_payload() const;
    VSOMEIP_EXPORT void set_payload(std::shared_ptr< payload > _payload);

    VSOMEIP_EXPORT bool serialize(serializer *_to) const;
    VSOMEIP_EXPORT bool deserialize(deserializer *_from);
};

} // namespace vsomeip

#endif // VSOMEIP_COMPAT_MESSAGE_IMPL_HPP_
