// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <limits>

#include "../include/deregister_application_command.hpp"

namespace vsomeip_v3 {
namespace protocol {

deregister_application_command::deregister_application_command()
    : simple_command(id_e::DEREGISTER_APPLICATION_ID) {

}

} // namespace protocol
} // namespace vsomeip
