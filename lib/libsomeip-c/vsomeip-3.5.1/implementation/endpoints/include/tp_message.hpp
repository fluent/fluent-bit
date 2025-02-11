// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TP_MESSAGE_HPP_
#define VSOMEIP_V3_TP_MESSAGE_HPP_

#include <set>
#include <chrono>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/enumeration_types.hpp>

#include "buffer.hpp"

#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif
namespace vsomeip_v3 {
namespace tp {

class tp_message {
public:
    tp_message(const byte_t* const _data, std::uint32_t _data_length,
               std::uint32_t _max_message_size);

    bool add_segment(const byte_t* const _data, std::uint32_t _data_length);

    message_buffer_t get_message();

    std::chrono::steady_clock::time_point get_creation_time() const;

private:
    std::string get_message_id(const byte_t* const _data, std::uint32_t _data_length);
    bool check_lengths(const byte_t* const _data, std::uint32_t _data_length,
                       length_t _segment_size, bool _more_fragments);
private:
    std::chrono::steady_clock::time_point timepoint_creation_;
    std::uint32_t max_message_size_;
    std::uint32_t current_message_size_;
    bool last_segment_received_;

    struct segment_t {
        segment_t(std::uint32_t _start, std::uint32_t _end) :
                start_(_start),
                end_(_end) {
        }

        bool operator<(const segment_t& _other) const {
            return start_ < _other.start_
                    || ((start_ >= _other.start_) && (end_ < _other.end_));
        };

        std::uint32_t start_;
        std::uint32_t end_;
    };
    std::set<segment_t> segments_;
    message_buffer_t message_;
};

} // namespace tp
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TP_MESSAGE_HPP_
