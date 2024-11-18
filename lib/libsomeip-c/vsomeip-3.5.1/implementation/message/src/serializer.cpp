// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//#include <cstring>

#ifdef VSOMEIP_DEBUGGING
#include <iomanip>
#include <sstream>
#endif

#include <vsomeip/internal/serializable.hpp>

#include "../include/serializer.hpp"
#include "../../utility/include/bithelper.hpp"
#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

serializer::serializer(std::uint32_t _buffer_shrink_threshold) :
        data_(0),
        shrink_count_(0),
        buffer_shrink_threshold_(_buffer_shrink_threshold) {
}

serializer::~serializer() {
}

bool serializer::serialize(const serializable *_from) {
    return (_from && _from->serialize(this));
}

bool serializer::serialize(const uint8_t _value) {
    data_.push_back(_value);
    return true;
}

bool serializer::serialize(const uint16_t _value) {
    uint8_t nvalue[2] = {0};
    bithelper::write_uint16_le(_value, nvalue);
    data_.push_back(nvalue[1]);
    data_.push_back(nvalue[0]);
    return true;
}

bool serializer::serialize(const uint32_t _value, bool _omit_last_byte) {
    uint8_t nvalue[4] = {0};
    bithelper::write_uint32_le(_value, nvalue);

    if (!_omit_last_byte) {
        data_.push_back(nvalue[3]);
    }
    data_.push_back(nvalue[2]);
    data_.push_back(nvalue[1]);
    data_.push_back(nvalue[0]);
    return true;
}

bool serializer::serialize(const uint8_t *_data, uint32_t _length) {
    try {
        data_.insert(data_.end(), _data, _data + _length);
    } catch(const std::bad_alloc &e) {
        VSOMEIP_ERROR << "Couldn't allocate memory in serializer::serialize(*_data, length)" << e.what();
        return false;
    }
    return true;
}

bool serializer::serialize(const std::vector<byte_t> &_data) {
    try {
        data_.insert(data_.end(),_data.begin(), _data.end());
    } catch(const std::bad_alloc &e) {
        VSOMEIP_ERROR << "Couldn't allocate memory in serializer::serialize(vector)" << e.what();
        return false;
    }
    return true;
}

const byte_t * serializer::get_data() const {
    return data_.data();
}

uint32_t serializer::get_capacity() const {
    return static_cast<std::uint32_t>(data_.max_size());
}

uint32_t serializer::get_size() const {
    return static_cast<std::uint32_t>(data_.size());
}

void serializer::set_data(byte_t *_data, uint32_t _capacity) {
    data_.clear();
    try {
        data_.insert(data_.end(), _data, _data + _capacity);
    } catch(const std::bad_alloc &e) {
        VSOMEIP_ERROR << "Couldn't allocate memory in serializer::set_data" << e.what();
    }
}

void serializer::reset() {
    if (buffer_shrink_threshold_) {
        if (data_.size() < (data_.capacity() >> 1)) {
            shrink_count_++;
        } else {
            shrink_count_ = 0;
        }
    }
    data_.clear();
    if (buffer_shrink_threshold_ && shrink_count_ > buffer_shrink_threshold_) {
        data_.shrink_to_fit();
        shrink_count_ = 0;
    }
}

#ifdef VSOMEIP_DEBUGGING
void serializer::show() {
    std::stringstream its_data;
    its_data << "SERIALIZED: "
             << std::setfill('0') << std::hex;
    for (const byte_t& e : data_)
        its_data << std::setw(2) << (int)e;
    VSOMEIP_INFO << its_data.str();
}
#endif

} // namespace vsomeip_v3
