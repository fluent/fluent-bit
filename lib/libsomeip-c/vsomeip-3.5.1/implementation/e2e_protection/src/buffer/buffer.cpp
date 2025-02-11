// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../../../e2e_protection/include/buffer/buffer.hpp"
#include <iomanip>

namespace vsomeip_v3 {

std::ostream &operator<<(std::ostream &_os, const e2e_buffer &_buffer) {
    for (auto b : _buffer) {
        if (isupper(b)) {
            _os << b;
        } else {
            _os << "[" << std::setfill('0') << std::setw(2) << std::hex << (uint32_t)b << std::dec << "]";
        }
    }
    return _os;
}

} // namespace vsomeip_v3
