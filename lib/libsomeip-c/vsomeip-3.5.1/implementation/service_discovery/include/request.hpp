// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_REQUEST_HPP_
#define VSOMEIP_V3_SD_REQUEST_HPP_

#include <memory>

#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

class endpoint;

namespace sd {

class request {
public:
    request(major_version_t _major, minor_version_t _minor, ttl_t _ttl);

    major_version_t get_major() const;
    void set_major(major_version_t _major);

    minor_version_t get_minor() const;
    void set_minor(minor_version_t _minor);

    ttl_t get_ttl() const;
    void set_ttl(ttl_t _ttl);

    uint8_t get_sent_counter() const;
    void set_sent_counter(uint8_t _sent_counter);

private:
    major_version_t major_;
    minor_version_t minor_;
    ttl_t ttl_;

    uint8_t sent_counter_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_REQUEST_HPP_
