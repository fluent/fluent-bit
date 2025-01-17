// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstring>

#ifdef VSOMEIP_DEBUGGING
#include <iomanip>
#include <sstream>
#endif
#include <vsomeip/internal/logger.hpp>

#include "../include/message_impl.hpp"
#include "../include/deserializer.hpp"
#include "../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {

deserializer::deserializer(std::uint32_t _buffer_shrink_threshold)
    : position_(data_.begin()),
      remaining_(0),
      buffer_shrink_threshold_(_buffer_shrink_threshold),
      shrink_count_(0) {
}

deserializer::deserializer(byte_t *_data, std::size_t _length,
                           std::uint32_t _buffer_shrink_threshold)
    : data_(_data, _data + _length),
      position_(data_.begin()),
      remaining_(_length),
      buffer_shrink_threshold_(_buffer_shrink_threshold),
      shrink_count_(0) {
}

deserializer::deserializer(const deserializer &_other)
    : data_(_other.data_),
      position_(_other.position_),
      remaining_(_other.remaining_),
      buffer_shrink_threshold_(_other.buffer_shrink_threshold_),
      shrink_count_(_other.shrink_count_) {
}

deserializer::~deserializer() {
}

std::size_t deserializer::get_available() const {
    return data_.size();
}

std::size_t deserializer::get_remaining() const {
    return remaining_;
}

void deserializer::set_remaining(std::size_t _remaining) {
    remaining_ = _remaining;
}

bool deserializer::deserialize(uint8_t& _value) {
    if (0 == remaining_)
        return false;

    _value = *position_++;

    remaining_--;
    return true;
}

bool deserializer::deserialize(uint16_t& _value) {
    if (2 > remaining_)
        return false;

    uint8_t byte0, byte1;
    byte0 = *position_++;
    byte1 = *position_++;
    remaining_ -= 2;

    uint8_t payload[2] = {byte0, byte1};
    _value = bithelper::read_uint16_be(payload);

    return true;
}

bool deserializer::deserialize(uint32_t &_value, bool _omit_last_byte) {
    if (3 > remaining_ || (!_omit_last_byte && 4 > remaining_))
        return false;

    uint8_t byte0 = 0, byte1, byte2, byte3;
    if (!_omit_last_byte) {
        byte0 = *position_++;
        remaining_--;
    }
    byte1 = *position_++;
    byte2 = *position_++;
    byte3 = *position_++;
    remaining_ -= 3;

    uint8_t payload[4] = {byte0, byte1, byte2, byte3};
    _value = bithelper::read_uint32_be(payload);

    return true;
}

bool deserializer::deserialize(uint8_t *_data, std::size_t _length) {
    if (_length > remaining_)
        return false;

    std::memcpy(_data, &data_[static_cast<std::vector<byte_t>::size_type>(position_ - data_.begin())], _length);
    position_ += static_cast<std::vector<byte_t>::difference_type>(_length);
    remaining_ -= _length;

    return true;
}

bool deserializer::deserialize(std::string &_target, std::size_t _length) {
    if (_length > remaining_ || _length > _target.capacity()) {
        return false;
    }
    _target.assign(position_, position_ + static_cast<std::vector<byte_t>::difference_type>(_length));
    position_ += static_cast<std::vector<byte_t>::difference_type>(_length);
    remaining_ -= _length;

    return true;
}

bool deserializer::deserialize(std::vector< uint8_t >& _value) {
    if (_value.capacity() > remaining_)
        return false;

    _value.assign(position_, position_
            + static_cast<std::vector<byte_t>::difference_type>(_value.capacity()));
    position_ += static_cast<std::vector<byte_t>::difference_type>(_value.capacity());
    remaining_ -= _value.capacity();

    return true;
}

bool deserializer::look_ahead(std::size_t _index, uint8_t &_value) const {
    if (_index > remaining_)
        return false;

    _value = *(position_ + static_cast<std::vector<byte_t>::difference_type>(_index));

    return true;
}

bool deserializer::look_ahead(std::size_t _index, uint16_t &_value) const {
    if (_index+1 > remaining_)
        return false;

    std::vector< uint8_t >::iterator i = position_ +
            static_cast<std::vector<byte_t>::difference_type>(_index);
    _value = bithelper::read_uint16_be(&(*i));

    return true;
}

bool deserializer::look_ahead(std::size_t _index, uint32_t &_value) const {
    if (_index+3 > remaining_)
        return false;

    std::vector< uint8_t >::const_iterator i = position_ + static_cast<std::vector<byte_t>::difference_type>(_index);
    _value = bithelper::read_uint32_be(&(*i));

    return true;
}

message_impl * deserializer::deserialize_message() try {
    std::unique_ptr<message_impl> deserialized_message = std::make_unique<message_impl>();
    if (false == deserialized_message->deserialize(this)) {
        VSOMEIP_ERROR << "SOME/IP message deserialization failed!";
        deserialized_message = nullptr;
    }

    return deserialized_message.release();
}
catch (const std::exception& e) {
    VSOMEIP_ERROR << "SOME/IP message deserialization failed with exception: " << e.what();
    return nullptr;
}

void deserializer::set_data(const byte_t *_data,  std::size_t _length) {
    if (0 != _data) {
        data_.assign(_data, _data + _length);
        position_ = data_.begin();
        remaining_ = static_cast<std::vector<byte_t>::size_type>(data_.end() - position_);
    } else {
        data_.clear();
        position_ = data_.end();
        remaining_ = 0;
    }
}

void
deserializer::set_data(const std::vector<byte_t> &_data) {

    data_ = std::move(_data);
    position_ = data_.begin();
    remaining_ = data_.size();
}

void deserializer::append_data(const byte_t *_data, std::size_t _length) {
    std::vector<byte_t>::difference_type offset = (position_ - data_.begin());
    data_.insert(data_.end(), _data, _data + _length);
    position_ = data_.begin() + offset;
    remaining_ += _length;
}

void deserializer::drop_data(std::size_t _length) {
    if (position_ + static_cast<std::vector<byte_t>::difference_type>(_length) < data_.end())
        position_ += static_cast<std::vector<byte_t>::difference_type>(_length);
    else
        position_ = data_.end();
}

void deserializer::reset() {
    if (buffer_shrink_threshold_) {
        if (data_.size() < (data_.capacity() >> 1)) {
            shrink_count_++;
        } else {
            shrink_count_ = 0;
        }
    }
    data_.clear();
    position_ = data_.begin();
    remaining_ = data_.size();
    if (buffer_shrink_threshold_ && shrink_count_ > buffer_shrink_threshold_) {
        data_.shrink_to_fit();
        shrink_count_ = 0;
    }
}

#ifdef VSOMEIP_DEBUGGING
void deserializer::show() const {
    std::stringstream its_message;
    its_message << "("
            << std::hex << std::setw(2) << std::setfill('0')
            << (int)*position_ << ", "
            << std:: dec << remaining_ << ") "
            << std::hex << std::setfill('0');
    for (int i = 0; i < data_.size(); ++i)
        its_message << std::setw(2) << (int)data_[i] << " ";
    VSOMEIP_INFO << its_message;
}
#endif

} // namespace vsomeip_v3
