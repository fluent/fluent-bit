// Copyright (C) 2016-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/plugin_manager_impl.hpp"

namespace vsomeip_v3 {

std::shared_ptr<plugin_manager> plugin_manager::get() {
    return plugin_manager_impl::get();
}

} // namespace vsomeip_v3
