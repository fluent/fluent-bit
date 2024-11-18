// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_E2E_BUFFER_HPP
#define VSOMEIP_V3_E2E_BUFFER_HPP

#include <stdexcept>
#include <cstdint>
#include <ostream>
#include <vector>

namespace vsomeip_v3 {

using e2e_buffer = std::vector<uint8_t>;

class buffer_view {
  public:
    buffer_view(const uint8_t *_data_ptr, size_t _data_length)
        : data_ptr_(_data_ptr), data_length_(_data_length) {
    }

    buffer_view(const e2e_buffer &_buffer)
        : data_ptr_(_buffer.data()), data_length_(_buffer.size()) {}

    buffer_view(const e2e_buffer &_buffer, size_t _length)
        : data_ptr_(_buffer.data()), data_length_(_length) {
    }

     buffer_view(const e2e_buffer &_buffer, size_t _begin, size_t _end)
        : data_ptr_(_buffer.data() + _begin), data_length_(_end - _begin) {
    }

    const uint8_t *begin(void) const { return data_ptr_; }

    const uint8_t *end(void) const { return data_ptr_ + data_length_; }

    size_t data_length(void) const { return data_length_; }

private:
    const uint8_t *data_ptr_;
    size_t data_length_;
};

std::ostream &operator<<(std::ostream &_os, const e2e_buffer &_buffer);

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_E2E_BUFFER_HPP
