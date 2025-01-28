// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <compat/vsomeip/defines.hpp>
#include <vsomeip/runtime.hpp>

#include "../include/application_impl.hpp"
#include "../include/runtime_impl.hpp"
#include "../../message/include/message_impl.hpp"
#include "../../message/include/payload_impl.hpp"

namespace vsomeip {

std::shared_ptr<runtime> runtime_impl::the_runtime_
    = std::make_shared<runtime_impl>();

std::string
runtime_impl::get_property(const std::string &_name) {

    return vsomeip_v3::runtime::get_property(_name);
}

void
runtime_impl::set_property(const std::string &_name, const std::string &_value) {

    vsomeip_v3::runtime::set_property(_name, _value);
}

std::shared_ptr<runtime>
runtime_impl::get() {

    return the_runtime_;
}

runtime_impl::~runtime_impl() {
}

std::shared_ptr<application>
runtime_impl::create_application(const std::string &_name) {
    std::lock_guard<std::mutex> its_lock(applications_mutex_);
    auto its_application = std::make_shared<application_impl>(_name);
    applications_[its_application->get_name()] = its_application;
    return (its_application);
}

std::shared_ptr<message>
runtime_impl::create_message(bool _reliable) const {

    auto its_impl = vsomeip_v3::runtime::get()->create_message(_reliable);
    return (std::make_shared<message_impl>(its_impl));
}

std::shared_ptr<message>
runtime_impl::create_request(bool _reliable) const {

    auto its_impl = vsomeip_v3::runtime::get()->create_request(_reliable);
    return (std::make_shared<message_impl>(its_impl));
}

std::shared_ptr<message>
runtime_impl::create_response(const std::shared_ptr<message> &_request) const {

    auto its_request = std::dynamic_pointer_cast<message_impl>(_request);
    auto its_impl = vsomeip_v3::runtime::get()->create_response(
            its_request->get_impl());
    return (std::make_shared<message_impl>(its_impl));
}

std::shared_ptr<message>
runtime_impl::create_notification(bool _reliable) const {

    auto its_impl = vsomeip_v3::runtime::get()->create_notification(_reliable);
    return (std::make_shared<message_impl>(its_impl));
}

std::shared_ptr<payload>
runtime_impl::create_payload() const {

    auto its_impl = vsomeip_v3::runtime::get()->create_payload();
    return (std::make_shared<payload_impl>(its_impl));
}

std::shared_ptr<payload>
runtime_impl::create_payload(const byte_t *_data, uint32_t _size) const {

    auto its_impl = vsomeip_v3::runtime::get()->create_payload(_data, _size);
    return (std::make_shared<payload_impl>(its_impl));
}

std::shared_ptr<payload>
runtime_impl::create_payload(const std::vector<byte_t> &_data) const {

    auto its_impl = vsomeip_v3::runtime::get()->create_payload(_data);
    return (std::make_shared<payload_impl>(its_impl));
}

std::shared_ptr<application>
runtime_impl::get_application(const std::string &_name) const {

    std::lock_guard<std::mutex> its_lock(applications_mutex_);
    auto found_application = applications_.find(_name);
    if (found_application != applications_.end())
        return found_application->second.lock();

    return (nullptr);
}

void
runtime_impl::remove_application(const std::string &_name) {

    std::lock_guard<std::mutex> its_lock(applications_mutex_);
    auto found_application = applications_.find(_name);
    if(found_application != applications_.end()) {
        applications_.erase(_name);
    }
}

} // namespace vsomeip
