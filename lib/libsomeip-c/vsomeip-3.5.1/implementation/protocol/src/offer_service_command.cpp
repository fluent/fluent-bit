// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/offer_service_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

offer_service_command::offer_service_command()
    : service_command_base(id_e::OFFER_SERVICE_ID) {

}

} // namespace protocol
} // namespace vsomeip
