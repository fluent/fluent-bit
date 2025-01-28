// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TP_REASSEMBLER_HPP_
#define VSOMEIP_V3_TP_REASSEMBLER_HPP_

#include <cstdint>
#include <map>
#include <mutex>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>

#include <vsomeip/primitive_types.hpp>

#include "tp_message.hpp"

#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {
namespace tp {

class tp_reassembler : public std::enable_shared_from_this<tp_reassembler> {
public:
    tp_reassembler(std::uint32_t _max_message_size, boost::asio::io_context &_io);
    /**
     * @return Returns a pair consisting of a bool and a message_buffer_t. The
     * value of the bool is set to true if the pair contains a finished message
     */
    std::pair<bool, message_buffer_t> process_tp_message(
            const byte_t* const _data, std::uint32_t _data_size,
            const boost::asio::ip::address& _address, std::uint16_t _port);
    bool cleanup_unfinished_messages();
    void stop();

private:
    void cleanup_timer_start(bool _force);
    void cleanup_timer_start_unlocked(bool _force);
    void cleanup_timer_cbk(const boost::system::error_code _error);

private:
    const std::uint32_t max_message_size_;
    std::mutex cleanup_timer_mutex_;
    bool cleanup_timer_running_;
    boost::asio::steady_timer cleanup_timer_;

    std::mutex mutex_;
    std::map<boost::asio::ip::address, std::map<std::uint16_t,
        std::map<std::uint64_t, std::pair<session_t, tp_message>>>> tp_messages_;
};

} // namespace tp
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_TP_REASSEMBLER_HPP_
