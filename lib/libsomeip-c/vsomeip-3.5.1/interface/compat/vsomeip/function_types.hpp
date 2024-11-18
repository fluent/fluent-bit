// Copyright (C) 2016-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_FUNCTION_TYPES_HPP
#define VSOMEIP_FUNCTION_TYPES_HPP

#include <functional>
#include <memory>

namespace vsomeip {

class payload;

typedef std::function<
    bool (const std::shared_ptr<payload> &,
          const std::shared_ptr<payload> &) > epsilon_change_func_t;

} // namespace vsomeip

#endif // VSOMEIP_FUNCTION_TYPES_HPP
