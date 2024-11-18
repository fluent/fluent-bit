// Copyright (C) 2014-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_BITHELPER_HPP
#define VSOMEIP_V3_BITHELPER_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <vsomeip/enumeration_types.hpp>
#include <algorithm>

namespace vsomeip_v3 {

class bithelper {
public:
    bithelper() = delete;

    //Write Methods
    inline static void write_uint16_be(uint16_t _value, uint8_t* _buffer) {
        if (get_endianness() != endianess_e::be) {
            _value = swap_endianness(_value);
        }
        std::memcpy(_buffer, reinterpret_cast<const uint8_t*>(&_value), sizeof(_value));
    }

    inline static void write_uint16_le(uint16_t _value, uint8_t* _buffer) {
        if (get_endianness() != endianess_e::le) {
            _value = swap_endianness(_value);
        }
        std::memcpy(_buffer, reinterpret_cast<const uint8_t*>(&_value), sizeof(_value));
    }

    inline static void write_uint32_be(uint32_t _value, uint8_t* _buffer) {
        if (get_endianness() != endianess_e::be) {
            _value = swap_endianness(_value);
        }
        std::memcpy(_buffer, reinterpret_cast<const uint8_t*>(&_value), sizeof(_value));
    }

    inline static void write_uint32_le(uint32_t _value, uint8_t* _buffer) {
        if (get_endianness() != endianess_e::le) {
            _value = swap_endianness(_value);
        }
        std::memcpy(_buffer, reinterpret_cast<const uint8_t*>(&_value), sizeof(_value));
    }

    inline static void write_uint64_be(uint64_t _value, uint8_t* _buffer) {
        if (get_endianness() != endianess_e::be) {
            _value = swap_endianness(_value);
        }
        std::memcpy(_buffer, reinterpret_cast<const uint8_t*>(&_value), sizeof(_value));
    }

    inline static void write_uint64_le(uint64_t _value, uint8_t* _buffer) {
        if (get_endianness() != endianess_e::le) {
            _value = swap_endianness(_value);
        }
        std::memcpy(_buffer, reinterpret_cast<const uint8_t*>(&_value), sizeof(_value));
    }

    //Read Methods
    inline static uint16_t read_uint16_be(const uint8_t* _buffer) {
        uint16_t value = 0;
        std::memcpy(&value, _buffer, sizeof(value));
        return get_endianness() == endianess_e::be ? value : swap_endianness(value);
    }

    inline static uint16_t read_uint16_le(const uint8_t* _buffer) {
        uint16_t value = 0;
        std::memcpy(&value, _buffer, sizeof(value));
        return get_endianness() == endianess_e::le ? value : swap_endianness(value);
    }

    inline static uint32_t read_uint32_be(const uint8_t* _buffer) {
        uint32_t value = 0;
        std::memcpy(&value, _buffer, sizeof(value));
        return get_endianness() == endianess_e::be ? value : swap_endianness(value);
    }

    inline static uint32_t read_uint32_le(const uint8_t* _buffer) {
        uint32_t value = 0;
        std::memcpy(&value, _buffer, sizeof(value));
        return get_endianness() == endianess_e::le ? value : swap_endianness(value);
    }

    inline static uint64_t read_uint64_be(const uint8_t* _buffer) {
        uint64_t value = 0;
        std::memcpy(&value, _buffer, sizeof(value));
        return get_endianness() == endianess_e::be ? value : swap_endianness(value);
    }

    inline static uint64_t read_uint64_le(const uint8_t* _buffer) {
        uint64_t value = 0;
        std::memcpy(&value, _buffer, sizeof(value));
        return get_endianness() == endianess_e::le ? value : swap_endianness(value);
    }

    inline static uint16_t read_high_word(uint32_t input) {
        return uint16_t((input >> 16) & 0xFFFF);
    }

    inline static uint16_t read_low_word(uint32_t input) {
        return uint16_t((input) & 0xFFFF);
    }

    template <typename T>
    static T swap_endianness(T _value) {
        static_assert(std::is_integral<T>::value, "Only integral types can be swapped");
        T swapped{};
        const auto src = reinterpret_cast<unsigned char*>(&_value);
        auto dst = reinterpret_cast<unsigned char*>(&swapped);
        std::reverse_copy(src, src + sizeof(T), dst);
        return swapped;
    }

#if defined(COMPILE_TIME_ENDIAN) && (COMPILE_TIME_ENDIAN == BYTEORDER_LITTLE_ENDIAN)
    static constexpr endianess_e get_endianness() { return endianess_e::le; }
#elif defined(COMPILE_TIME_ENDIAN) && (COMPILE_TIME_ENDIAN == BYTEORDER_BIG_ENDIAN)
    static constexpr Endianness get_endianness() { return endianess_e::be; }
#else
    // Run-time check
    static endianess_e get_endianness() {
        uint16_t test{0x0102};
        return (*reinterpret_cast<uint8_t*>(&test) == 1) ? endianess_e::be : endianess_e::le;
    }
#endif
};

}

#endif // VSOMEIP_V3_BITHELPER_HPP
