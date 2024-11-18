// Copyright (C) 2019-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/tp.hpp"

#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif // ANDROID

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
#include <arpa/inet.h>
#else
#include <Winsock2.h>
#endif


namespace vsomeip_v3 {
namespace tp {

tp_split_messages_t
tp::tp_split_message(const std::uint8_t * const _data, std::uint32_t _size,
        std::uint16_t _max_segment_length) {

    tp_split_messages_t split_messages;

    if (_size < VSOMEIP_MAX_UDP_MESSAGE_SIZE) {
        VSOMEIP_ERROR << __func__ << " called with size: " << std::dec << _size;
        return split_messages;
    }

    const auto data_end = _data + _size;
    for (auto current_offset = _data + VSOMEIP_FULL_HEADER_SIZE; current_offset < data_end;) {
        auto msg = std::make_shared<message_buffer_t>();
        msg->reserve(VSOMEIP_FULL_HEADER_SIZE + sizeof(tp_header_t) + _max_segment_length);
        // copy the header
        msg->insert(msg->end(), _data, _data + VSOMEIP_FULL_HEADER_SIZE);
        // change the message type
        (*msg)[VSOMEIP_MESSAGE_TYPE_POS] = (*msg)[VSOMEIP_MESSAGE_TYPE_POS] | 0x20;
        // check if last segment
        const auto segment_end = current_offset + _max_segment_length;
        const bool is_last_segment = (segment_end >= data_end);
        // insert tp_header
        const tp_header_t header = htonl(
                static_cast<tp_header_t>((current_offset - VSOMEIP_FULL_HEADER_SIZE - _data)) |
                static_cast<tp_header_t>(is_last_segment ? 0x0u : 0x1u));

        const byte_t * const headerp = reinterpret_cast<const byte_t*>(&header);
        msg->insert(msg->end(), headerp, headerp + sizeof(tp_header_t));

        // insert payload
        if (is_last_segment) {
            msg->insert(msg->end(), current_offset, data_end);
            current_offset = data_end;
        } else {
            msg->insert(msg->end(), current_offset, segment_end);
            current_offset += _max_segment_length;
        }
        // update length
        const length_t its_length = static_cast<length_t>(msg->size()
                                                - VSOMEIP_SOMEIP_HEADER_SIZE);
        *(reinterpret_cast<length_t*>(&(*msg)[VSOMEIP_LENGTH_POS_MIN])) = htonl(its_length);
        split_messages.emplace_back(std::move(msg));
    }

    return split_messages;
}

const std::uint16_t tp::tp_max_segment_length_;

} // namespace tp
} // namespace vsomeip_v3
