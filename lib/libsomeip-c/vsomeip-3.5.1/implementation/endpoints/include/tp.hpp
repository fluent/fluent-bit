// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TP_HPP_
#define VSOMEIP_V3_TP_HPP_

#include <cstdint>
#include <vector>
#include <utility>
#include <memory>

#include <vsomeip/enumeration_types.hpp>

#include "buffer.hpp"

namespace vsomeip_v3 {
namespace tp {

#define VSOMEIP_TP_HEADER_SIZE       4
#define VSOMEIP_TP_HEADER_POS_MIN   16
#define VSOMEIP_TP_HEADER_POS_MAX   19
#define VSOMEIP_TP_PAYLOAD_POS      20

// 28 bit length + 3 bit reserved + 1 bit more segments
typedef std::uint32_t tp_header_t;
typedef std::uint8_t tp_message_type_t;
typedef std::vector<message_buffer_ptr_t> tp_split_messages_t;

const std::uint8_t TP_FLAG = 0x20;

class tp {
public:
    static inline length_t get_offset(tp_header_t _tp_header) {
        return _tp_header & 0xfffffff0;
    };
    static inline bool more_segments(tp_header_t _tp_header) {
        return _tp_header & 0x1;
    };
    static inline bool tp_flag_is_set(tp_message_type_t _msg_type) {
        return _msg_type & TP_FLAG;
    };
    static inline tp_message_type_t tp_flag_set(message_type_e _msg_type) {
        return static_cast<tp_message_type_t>(_msg_type) | TP_FLAG;
    }
    static inline message_type_e tp_flag_unset(tp_message_type_t _msg_type) {
        return static_cast<message_type_e>(_msg_type & ~TP_FLAG);
    }

    static tp_split_messages_t tp_split_message(
            const std::uint8_t * const _data, std::uint32_t _size,
            std::uint16_t _max_segment_length);

    static const std::uint16_t tp_max_segment_length_ = 1392;
};

} // namespace tp
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TP_HPP_
