// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "../include/tp_reassembler.hpp"

#include <vsomeip/defines.hpp>
#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/tp.hpp"
#include "../../utility/include/bithelper.hpp"

#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif // ANDROID

namespace vsomeip_v3 {
namespace tp {

tp_reassembler::tp_reassembler(std::uint32_t _max_message_size, boost::asio::io_context &_io) :
    max_message_size_(_max_message_size),
    cleanup_timer_running_(false),
    cleanup_timer_(_io) {
}

std::pair<bool, message_buffer_t> tp_reassembler::process_tp_message(
        const byte_t* const _data, std::uint32_t _data_size,
        const boost::asio::ip::address& _address, std::uint16_t _port) {
    std::pair<bool, message_buffer_t> ret;
    if (_data_size < VSOMEIP_FULL_HEADER_SIZE) {
        return std::make_pair(false, message_buffer_t());
    }

    cleanup_timer_start(false);

    const service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
    const method_t its_method   = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);
    const client_t its_client   = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
    const session_t its_session = bithelper::read_uint16_be(&_data[VSOMEIP_SESSION_POS_MIN]);
    const interface_version_t its_interface_version = _data[VSOMEIP_INTERFACE_VERSION_POS];
    const message_type_e its_msg_type = tp::tp_flag_unset(_data[VSOMEIP_MESSAGE_TYPE_POS]);

    const std::uint64_t its_tp_message_id = ((static_cast<std::uint64_t>(its_service) << 48) |
                                             (static_cast<std::uint64_t>(its_method) << 32) |
                                             (static_cast<std::uint64_t>(its_client) << 16) |
                                             (static_cast<std::uint64_t>(its_interface_version) << 8) |
                                             (static_cast<std::uint64_t>(its_msg_type)));

    std::lock_guard<std::mutex> its_lock(mutex_);
    ret.first = false;
    const auto found_ip = tp_messages_.find(_address);
    if (found_ip != tp_messages_.end()) {
        const auto found_port = found_ip->second.find(_port);
        if (found_port != found_ip->second.end()) {
            auto found_tp_msg = found_port->second.find(its_tp_message_id);
            if (found_tp_msg != found_port->second.end()) {
                if (found_tp_msg->second.first == its_session) {
                    // received additional segment for already known message
                    if (found_tp_msg->second.second.add_segment(_data, _data_size)) {
                        // message is complete
                        ret.first = true;
                        ret.second = found_tp_msg->second.second.get_message();
                        // cleanup tp_message as message was moved and cleanup map
                        found_port->second.erase(its_tp_message_id);
                        if (found_port->second.empty()) {
                            found_ip->second.erase(found_port);
                            if (found_ip->second.empty()) {
                                tp_messages_.erase(found_ip);
                            }
                        }
                    }
                } else {
                    VSOMEIP_WARNING << __func__ << ": Received new segment "
                            "although old one is not finished yet. Dropping "
                            "old. ("
                            << std::hex << std::setfill('0')
                            << std::setw(4) << its_client << ") ["
                            << std::setw(4) << its_service << "."
                            << std::setw(4) << its_method << "."
                            << std::setw(2) << std::uint32_t(its_interface_version) << "."
                            << std::setw(2) << std::uint32_t(its_msg_type) << "] Old: 0x"
                            << std::setw(4) << found_tp_msg->second.first << ", new: 0x"
                            << std::setw(4) << its_session;
                    // new segment with different session id -> throw away current
                    found_tp_msg->second.first = its_session;
                    found_tp_msg->second.second = tp_message(_data, _data_size, max_message_size_);
                }
            } else {
                found_port->second.emplace(
                        std::make_pair(its_tp_message_id,
                                std::make_pair(its_session,
                                        tp_message(_data, _data_size, max_message_size_))));
            }
        } else {
            found_ip->second[_port].emplace(
                    std::make_pair(its_tp_message_id,
                            std::make_pair(its_session,
                                    tp_message(_data, _data_size, max_message_size_))));
        }
    } else {
        tp_messages_[_address][_port].emplace(
                std::make_pair(its_tp_message_id,
                        std::make_pair(its_session,
                                tp_message(_data, _data_size, max_message_size_))));
    }
    return ret;
}

bool tp_reassembler::cleanup_unfinished_messages() {
    std::lock_guard<std::mutex> its_lock(mutex_);
    const std::chrono::steady_clock::time_point now =
            std::chrono::steady_clock::now();
    for (auto ip_iter = tp_messages_.begin(); ip_iter != tp_messages_.end();) {
        for (auto port_iter = ip_iter->second.begin();
                port_iter != ip_iter->second.end();) {
            for (auto tp_id_iter = port_iter->second.begin();
                    tp_id_iter != port_iter->second.end();) {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - tp_id_iter->second.second.get_creation_time()).count()
                        > 5000) {
                    // message is older than 5 seconds delete it
                    const auto its_service = static_cast<service_t>(tp_id_iter->first >> 48);
                    const auto its_method = static_cast<method_t>(tp_id_iter->first >> 32);
                    const auto its_client = static_cast<client_t>(tp_id_iter->first >> 16);
                    const auto its_interface_version = static_cast<interface_version_t>(tp_id_iter->first >> 8);
                    const auto its_msg_type = static_cast<message_type_e>(tp_id_iter->first >> 0);
                    VSOMEIP_WARNING << __func__
                            << ": deleting unfinished SOME/IP-TP message from: "
                            << ip_iter->first.to_string() << ":" << std::dec
                            << port_iter->first << " ("
                            << std::hex << std::setfill('0')
                            << std::setw(4) << its_client << ") ["
                            << std::setw(4) << its_service << "."
                            << std::setw(4) << its_method << "."
                            << std::setw(2) << std::uint32_t(its_interface_version) << "."
                            << std::setw(2) << std::uint32_t(its_msg_type) << "."
                            << std::setw(4) << tp_id_iter->second.first << "]";
                    tp_id_iter = port_iter->second.erase(tp_id_iter);
                } else {
                    tp_id_iter++;
                }
            }
            if (port_iter->second.empty()) {
                port_iter = ip_iter->second.erase(port_iter);
            } else {
                port_iter++;
            }
        }
        if (ip_iter->second.empty()) {
            ip_iter = tp_messages_.erase(ip_iter);
        } else {
            ip_iter++;
        }
    }
    return !tp_messages_.empty();
}

void tp_reassembler::stop() {
    std::lock_guard<std::mutex> its_lock(cleanup_timer_mutex_);
    boost::system::error_code ec;
    cleanup_timer_.cancel(ec);
}

void tp_reassembler::cleanup_timer_start(bool _force) {
    std::lock_guard<std::mutex> its_lock(cleanup_timer_mutex_);
    cleanup_timer_start_unlocked(_force);
}

void tp_reassembler::cleanup_timer_start_unlocked(bool _force) {
    if (!cleanup_timer_running_ || _force) {
        cleanup_timer_.expires_from_now(std::chrono::seconds(5));
        cleanup_timer_running_ = true;
        cleanup_timer_.async_wait(
                std::bind(&tp_reassembler::cleanup_timer_cbk,
                        shared_from_this(), std::placeholders::_1));
    }
}

void tp_reassembler::cleanup_timer_cbk(
        const boost::system::error_code _error) {
    if (!_error) {
        std::lock_guard<std::mutex> its_lock(cleanup_timer_mutex_);
        if (cleanup_unfinished_messages()) {
            cleanup_timer_start_unlocked(true);
        } else {
            // don't start timer again as there are no more segmented messages present
            cleanup_timer_running_ = false;
        }
    }
}

} //namespace tp
} // namespace vsomeip_v3
