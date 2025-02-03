// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <compat/vsomeip/runtime.hpp>
#include "../include/runtime_impl.hpp"

namespace vsomeip {

std::string
runtime::get_property(const std::string &_name) {

    return runtime_impl::get_property(_name);
}

void
runtime::set_property(const std::string &_name, const std::string &_value) {

    runtime_impl::set_property(_name, _value);
}

std::shared_ptr<runtime>
runtime::get() {

    return runtime_impl::get();
}

} // namespace vsomeip
