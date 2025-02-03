// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_FUNCTION_TYPES_HPP_
#define VSOMEIP_V3_FUNCTION_TYPES_HPP_

#include <functional>
#include <memory>

namespace vsomeip_v3 {

class payload;

typedef std::function<
    bool (const std::shared_ptr<payload> &,
          const std::shared_ptr<payload> &) > epsilon_change_func_t;

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_FUNCTION_TYPES_HPP_
