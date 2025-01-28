// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/request.hpp"

namespace vsomeip_v3 {
namespace sd {

request::request(major_version_t _major, minor_version_t _minor, ttl_t _ttl)
        : major_(_major), minor_(_minor), ttl_(_ttl), sent_counter_(0) {
}

major_version_t request::get_major() const {
    return major_;
}

void request::set_major(major_version_t _major) {
    major_ = _major;
}

minor_version_t request::get_minor() const {
    return minor_;
}

void request::set_minor(minor_version_t _minor) {
    minor_ = _minor;
}

ttl_t request::get_ttl() const {
    return ttl_;
}

void request::set_ttl(ttl_t _ttl) {
    ttl_ = _ttl;
}

uint8_t request::get_sent_counter() const {
    return sent_counter_;
}

void request::set_sent_counter(uint8_t _sent_counter) {
    sent_counter_ = _sent_counter;
}

}  // namespace sd
}  // namespace vsomeip_v3
