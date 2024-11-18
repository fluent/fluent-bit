// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <ostream>
#include "../../../e2e_protection/include/e2exf/config.hpp"

namespace vsomeip_v3 {

std::ostream &operator<<(std::ostream &_os, const e2exf::data_identifier_t &_data_identifier) {
    _os << _data_identifier.first << _data_identifier.second;
    return _os;
}

} // namespace vsomeip_v3
