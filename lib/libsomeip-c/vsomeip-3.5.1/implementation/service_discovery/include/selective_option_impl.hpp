// Copyright (C) 2018-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_SELECTIVE_OPTION_IMPL_HPP
#define VSOMEIP_V3_SD_SELECTIVE_OPTION_IMPL_HPP

#include <set>

#include <vsomeip/primitive_types.hpp>

#include "option_impl.hpp"

namespace vsomeip_v3 {

class serializer;
class deserializer;

namespace sd {

class selective_option_impl: public option_impl {

public:
    selective_option_impl();
    virtual ~selective_option_impl();

    bool equals(const option_impl &_other) const;

    std::set<client_t> get_clients() const;
    void set_clients(const std::set<client_t> &_clients);
    bool add_client(client_t _client);
    bool remove_client(client_t _client);
    bool has_clients() const;
    bool has_client(client_t _client);

    bool serialize(vsomeip_v3::serializer *_to) const;
    bool deserialize(vsomeip_v3::deserializer *_from);

private:
    std::set<client_t> clients_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_SELECTIVE_OPTION_IMPL_HPP
