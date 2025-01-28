// Copyright (C) 2019-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <sstream>

#include <vsomeip/internal/logger.hpp>

#include "../include/tp_message.hpp"
#include "../include/tp.hpp"
#include "../../utility/include/bithelper.hpp"

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

tp_message::tp_message(const byte_t* const _data, std::uint32_t _data_length,
                       std::uint32_t _max_message_size) :
    timepoint_creation_(std::chrono::steady_clock::now()),
    max_message_size_(_max_message_size),
    current_message_size_(0),
    last_segment_received_(false) {
    if (_data_length < VSOMEIP_FULL_HEADER_SIZE + VSOMEIP_TP_HEADER_SIZE) {
        VSOMEIP_ERROR << __func__ << " received too short SOME/IP-TP message "
                << get_message_id(_data, _data_length);
        return;
    }
    // copy header
    message_.insert(message_.end(), _data, _data + VSOMEIP_FULL_HEADER_SIZE);
    // remove TP flag
    message_[VSOMEIP_MESSAGE_TYPE_POS] = static_cast<byte_t>(tp::tp_flag_unset(
                                            message_[VSOMEIP_MESSAGE_TYPE_POS]));

    const length_t its_segment_size = _data_length - VSOMEIP_FULL_HEADER_SIZE
                                        - VSOMEIP_TP_HEADER_SIZE;
    const tp_header_t its_tp_header = bithelper::read_uint32_be(&_data[VSOMEIP_TP_HEADER_POS_MIN]);

    if (check_lengths(_data, _data_length, its_segment_size,
            tp::more_segments(its_tp_header))) {
        const length_t its_offset = tp::get_offset(its_tp_header);
        segments_.emplace(segment_t(its_offset, its_offset + its_segment_size - 1));
        if (its_offset != 0) {
            // segment different than the first segment was received
            message_.resize(VSOMEIP_FULL_HEADER_SIZE + its_offset, 0x0);
            if (!tp::more_segments(its_tp_header)) {
                // received the last segment of the segmented message first
                last_segment_received_ = true;
            }
        }
        message_.insert(message_.end(), &_data[VSOMEIP_TP_PAYLOAD_POS],
                                        &_data[VSOMEIP_TP_PAYLOAD_POS] + its_segment_size);
        current_message_size_ += VSOMEIP_FULL_HEADER_SIZE + its_segment_size;
    }
}

bool tp_message::add_segment(const byte_t* const _data,
                             std::uint32_t _data_length) {
    if (_data_length < VSOMEIP_FULL_HEADER_SIZE + VSOMEIP_TP_HEADER_SIZE) {
        VSOMEIP_ERROR << __func__ << " received too short SOME/IP-TP message "
                << get_message_id(_data, _data_length);
        return false;
    }
    bool ret = false;

    const length_t its_segment_size = _data_length - VSOMEIP_FULL_HEADER_SIZE
                                        - VSOMEIP_TP_HEADER_SIZE;
    const tp_header_t its_tp_header = bithelper::read_uint32_be(&_data[VSOMEIP_TP_HEADER_POS_MIN]);

    if (check_lengths(_data, _data_length, its_segment_size,
            tp::more_segments(its_tp_header))) {
        const length_t its_offset = tp::get_offset(its_tp_header);
        const auto emplace_res = segments_.emplace(
                segment_t(its_offset, its_offset + its_segment_size - 1));
        if (!emplace_res.second) {
            VSOMEIP_WARNING << __func__ << ":" << __LINE__
                    << " received duplicate segment " << get_message_id(_data, _data_length)
                    << "TP offset: 0x" << std::hex << its_offset;
        } else {
            const auto& seg_current = emplace_res.first;
            const auto& seg_next = std::next(seg_current);
            const bool current_segment_is_last = (seg_next == segments_.end());
            const bool current_segment_is_first = (seg_current == segments_.begin());
            if (current_segment_is_last) {
                if (current_segment_is_first) {
                    // received segment of message but the first received segment was invalid
                    // resize + append
                    VSOMEIP_WARNING << __func__ << ":" << __LINE__
                            << " received 2nd segment of message. But the "
                            "first received segment already wasn't accepted. "
                            "The message can't be completed anymore: "
                            << get_message_id(_data, _data_length);
                    if (its_offset != 0) {
                        // segment different than the first segment was received
                        message_.resize(VSOMEIP_FULL_HEADER_SIZE + its_offset, 0x0);
                        if (!tp::more_segments(its_tp_header)) {
                            // received the last segment of the segmented message first
                            last_segment_received_ = true;
                        }
                    }
                    // append to end of message
                    message_.insert(message_.end(), &_data[VSOMEIP_TP_PAYLOAD_POS],
                            &_data[VSOMEIP_TP_PAYLOAD_POS] + its_segment_size);
                    current_message_size_ += its_segment_size;
                } else {
                    const auto& seg_prev = std::prev(seg_current);
                    if (seg_prev->end_ < seg_current->start_) {
                        const bool direct_previous_segment_present = (seg_prev->end_ + 1 == seg_current->start_);
                        if (!direct_previous_segment_present) {
                            // received segment out of order behind the current end of received segments
                            //resize + append
                            message_.resize(VSOMEIP_FULL_HEADER_SIZE + its_offset, 0x0);
                        }
                        // append to end of message
                        message_.insert(message_.end(), &_data[VSOMEIP_TP_PAYLOAD_POS],
                                &_data[VSOMEIP_TP_PAYLOAD_POS] + its_segment_size);
                        current_message_size_ += its_segment_size;
                    } else {
                        // this segment starts before the end of the previous and
                        // would overwrite already received data
                        VSOMEIP_WARNING << __func__ << ":" << __LINE__
                                << " completely accepting segment would overwrite previous segment "
                                << get_message_id(_data, _data_length)
                                << "previous segment end: " << std::dec << seg_prev->end_ + 1
                                << " this segment start: " << std::dec << seg_current->start_;
                        message_.insert(message_.end(),
                                &_data[VSOMEIP_TP_PAYLOAD_POS] + ((seg_prev->end_ + 1) - seg_current->start_),
                                &_data[VSOMEIP_TP_PAYLOAD_POS] + its_segment_size);
                        // update start of current segment
                        const std::uint32_t current_end = seg_current->end_;
                        segments_.erase(seg_current);
                        segments_.emplace(segment_t(seg_prev->end_ + 1, current_end));
                        current_message_size_ += current_end - seg_prev->end_;
                    }
                }
            } else {
                // received segment in wrong order and other segments afterwards were already received
                if ((seg_current != segments_.begin() && std::prev(seg_current)->end_ < seg_current->start_)
                     || seg_current == segments_.begin()) { // no need to check prev_segment if current segment is the first
                    if (seg_current->end_ < seg_next->start_) {
                        std::memcpy(&message_[VSOMEIP_FULL_HEADER_SIZE + its_offset], &_data[VSOMEIP_TP_PAYLOAD_POS], its_segment_size);
                        current_message_size_ += its_segment_size;
                    } else {
                        // this segment ends after the start of the next and
                        // would overwrite already received data
                        VSOMEIP_WARNING << __func__ << ":" << __LINE__
                                << " completely accepting segment would overwrite next segment "
                                << get_message_id(_data, _data_length)
                                << "next segment start: " << std::dec << seg_next->start_
                                << " this segment end: " << std::dec << seg_current->end_ + 1;
                        std::memcpy(&message_[VSOMEIP_FULL_HEADER_SIZE + its_offset], &_data[VSOMEIP_TP_PAYLOAD_POS], seg_next->start_ - its_offset);
                        // update current segment length to match size of memory
                        std::uint32_t current_start = seg_current->start_;
                        segments_.erase(seg_current);
                        segments_.emplace(segment_t(current_start, seg_next->start_ - 1));
                        current_message_size_ += seg_next->start_ - current_start;
                    }
                } else if (seg_current->end_ < seg_next->start_) {
                    // this segment starts before the end of the previous and
                    // would overwrite already received data. But ends before the
                    // start of the next segment
                    const auto& seg_prev = std::prev(seg_current);
                    VSOMEIP_WARNING << __func__ << ":" << __LINE__
                            << " completely accepting segment would overwrite previous segment "
                            << get_message_id(_data, _data_length)
                            << "previous segment end: " << std::dec << seg_prev->end_
                            << " this segment start: " << std::dec << seg_current->start_;
                    const length_t its_corrected_offset = seg_prev->end_ + 1;
                    std::memcpy(&message_[VSOMEIP_FULL_HEADER_SIZE + its_corrected_offset],
                                &_data[VSOMEIP_TP_PAYLOAD_POS] + its_corrected_offset - its_offset,
                                seg_next->start_ - its_corrected_offset);
                    // update current segment length to match size of memory
                    std::uint32_t current_end = seg_current->end_;
                    segments_.erase(seg_current);
                    segments_.emplace(segment_t(seg_prev->end_ + 1, current_end));
                    current_message_size_ += current_end - seg_prev->end_;
                } else {
                    // this segment starts before the end of the previous and
                    // ends after the start of the next segment and would
                    // overwrite already received data.
                    const auto& seg_prev = std::prev(seg_current);
                    VSOMEIP_WARNING << __func__ << ":" << __LINE__
                            << " completely accepting segment would overwrite "
                            << "previous and next segment "
                            << get_message_id(_data, _data_length)
                            << "previous segment end: " << std::dec << seg_prev->end_
                            << " this segment start: " << std::dec << seg_current->start_
                            << " this segment end: " << std::dec << seg_current->end_
                            << " next segment start: " << std::dec << seg_next->start_;
                    const length_t its_corrected_offset = seg_prev->end_ + 1;
                    std::memcpy(&message_[VSOMEIP_FULL_HEADER_SIZE + its_corrected_offset],
                                &_data[VSOMEIP_TP_PAYLOAD_POS] + its_corrected_offset - its_offset,
                                seg_next->start_ - its_corrected_offset);
                    segments_.erase(seg_current);
                    segments_.emplace(segment_t(seg_prev->end_ + 1, seg_next->start_ - 1));
                    current_message_size_ += seg_next->start_ - (seg_prev->end_ + 1);
                }
            }
            if (!tp::more_segments(its_tp_header)) {
                // received the last segment
                last_segment_received_ = true;
            }
            if (last_segment_received_) {
                // check if all segments are present
                std::uint32_t last_end = std::numeric_limits<std::uint32_t>::max();
                bool complete(true);
                for (const auto& seg : segments_) {
                    if (last_end + 1 != seg.start_) {
                        complete = false;
                        break;
                    } else {
                        last_end = seg.end_;
                    }
                }
                if (complete) {
                    // all segments were received -> update length field of message
                    const length_t its_length = static_cast<length_t>(
                            message_.size() - VSOMEIP_SOMEIP_HEADER_SIZE);
                    *(reinterpret_cast<length_t*>(&message_[VSOMEIP_LENGTH_POS_MIN])) = htonl(its_length);
                    // all segments were received -> update return code field of message
                    message_[VSOMEIP_RETURN_CODE_POS] = _data[VSOMEIP_RETURN_CODE_POS];
                    ret = true;
                }
            }
        }
    }
    return ret;
}

message_buffer_t tp_message::get_message() {
    return std::move(message_);
}

std::chrono::steady_clock::time_point tp_message::get_creation_time() const {
    return timepoint_creation_;
}

std::string tp_message::get_message_id(const byte_t* const _data, std::uint32_t _data_length) {
    std::stringstream ss;
    if (_data_length >= VSOMEIP_FULL_HEADER_SIZE) {

        const service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
        const service_t its_method  = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);
        const service_t its_client  = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
        const service_t its_session = bithelper::read_uint16_be(&_data[VSOMEIP_SESSION_POS_MIN]);
        const interface_version_t its_interface_version =
                _data[VSOMEIP_INTERFACE_VERSION_POS];
        const message_type_e its_msg_type = tp::tp_flag_unset(
                _data[VSOMEIP_MESSAGE_TYPE_POS]);

        ss << "("
           << std::hex << std::setfill('0')
           << std::setw(4) << its_client << ") ["
           << std::setw(4) << its_service << "."
           << std::setw(4) << its_method << "."
           << std::setw(2) << std::uint32_t(its_interface_version) << "."
           << std::setw(2) << std::uint32_t(its_msg_type) << "."
           << std::setw(4) << its_session
           << "] ";
        if (_data_length > VSOMEIP_TP_HEADER_POS_MAX) {
            const tp_header_t its_tp_header = bithelper::read_uint32_be(&_data[VSOMEIP_TP_HEADER_POS_MIN]);
            const length_t its_offset = tp::get_offset(its_tp_header);
            ss << " TP offset: 0x" << std::hex << its_offset << " ";
        }
    }
    return ss.str();
}

bool tp_message::check_lengths(const byte_t* const _data,
                               std::uint32_t _data_length,
                               length_t _segment_size, bool _more_fragments) {

    const length_t its_length = bithelper::read_uint32_be(&_data[VSOMEIP_LENGTH_POS_MIN]);
    const tp_header_t its_tp_header = bithelper::read_uint32_be(&_data[VSOMEIP_TP_HEADER_POS_MIN]);
    bool ret(true);

    if (!tp::tp_flag_is_set(_data[VSOMEIP_MESSAGE_TYPE_POS])) {
        VSOMEIP_ERROR << __func__ << ": TP flag not set "
                << get_message_id(_data, _data_length);
        ret = false;
    } else if (_data_length != its_length + VSOMEIP_SOMEIP_HEADER_SIZE) {
        VSOMEIP_ERROR << __func__
                << ": data length doesn't match header length field"
                << get_message_id(_data, _data_length)
                << " data: " << std::dec << _data_length
                << " header: " << std::dec << its_length;
        ret = false;
    } else if (_segment_size != its_length - VSOMEIP_TP_HEADER_SIZE
            - (VSOMEIP_FULL_HEADER_SIZE - VSOMEIP_SOMEIP_HEADER_SIZE)) {
        VSOMEIP_ERROR << __func__
                << ": segment size doesn't align with header length field"
                << get_message_id(_data, _data_length)
                << "segment size: " << std::dec << _segment_size
                << " data: " << std::dec << _data_length
                << " header: " << std::dec << its_length;
        ret = false;
    } else if (_segment_size > tp::tp_max_segment_length_) {
        VSOMEIP_ERROR << __func__ << ": Segment exceeds allowed size "
                << get_message_id(_data, _data_length)
                << "segment size: " << std::dec << _segment_size << " (max. "
                << std::dec << tp::tp_max_segment_length_
                << ") data: " << std::dec << _data_length
                << " header: " << std::dec << its_length;
        ret = false;
    } else if (_more_fragments && _segment_size % 16 > 0) {
        VSOMEIP_ERROR << __func__ << ": Segment size not multiple of 16 "
                << get_message_id(_data, _data_length)
                << "segment size: " << std::dec << _segment_size
                << " data: " << std::dec << _data_length
                << " header: " << std::dec << its_length;
        ret = false;
    } else if (current_message_size_ + _segment_size > max_message_size_
            || current_message_size_ + _segment_size < _segment_size) { // overflow check
        VSOMEIP_ERROR << __func__ << ": Message exceeds maximum configured size: "
                << get_message_id(_data, _data_length)
                << "segment size: " << std::dec << _segment_size
                << " current message size: " << std::dec << current_message_size_
                << " maximum message size: " << std::dec << max_message_size_;
        ret = false;
    } else if (tp::get_offset(its_tp_header) + _segment_size > max_message_size_
            || tp::get_offset(its_tp_header) + _segment_size < _segment_size) { // overflow check
        VSOMEIP_ERROR << __func__ << ": SomeIP/TP offset field exceeds maximum configured message size: "
                << get_message_id(_data, _data_length)
                << " TP offset [bytes]: " << std::dec << tp::get_offset(its_tp_header)
                << " segment size: " << std::dec << _segment_size
                << " current message size: " << std::dec << current_message_size_
                << " maximum message size: " << std::dec << max_message_size_;
        ret = false;
    }
    return ret;
}

} // namespace tp
} // namespace vsomeip_v3
