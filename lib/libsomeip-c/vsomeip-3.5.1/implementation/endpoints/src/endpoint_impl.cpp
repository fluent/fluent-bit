// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/local/stream_protocol.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/endpoint_host.hpp"
#include "../../routing/include/routing_host.hpp"
#include "../include/endpoint_impl.hpp"

namespace vsomeip_v3 {

template<typename Protocol>
endpoint_impl<Protocol>::endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                                       const std::shared_ptr<routing_host>& _routing_host,
									   boost::asio::io_context &_io,
                                       const std::shared_ptr<configuration>& _configuration) :
    io_(_io), endpoint_host_(_endpoint_host), routing_host_(_routing_host),
	is_supporting_magic_cookies_(false), has_enabled_magic_cookies_(false), use_count_(0),
    sending_blocked_(false), configuration_(_configuration), is_supporting_someip_tp_(false) {
}

template<typename Protocol>
void endpoint_impl<Protocol>::enable_magic_cookies() {
    has_enabled_magic_cookies_ = is_supporting_magic_cookies_;
}

template<typename Protocol>
uint32_t endpoint_impl<Protocol>::find_magic_cookie(
        byte_t *_buffer, size_t _size) {
    bool is_found(false);
    uint32_t its_offset = 0xFFFFFFFF;

    uint8_t its_cookie_identifier, its_cookie_type;

    if (is_client()) {
        its_cookie_identifier =
                static_cast<uint8_t>(MAGIC_COOKIE_SERVICE_MESSAGE);
        its_cookie_type =
                static_cast<uint8_t>(MAGIC_COOKIE_SERVICE_MESSAGE_TYPE);
    } else {
        its_cookie_identifier =
                static_cast<uint8_t>(MAGIC_COOKIE_CLIENT_MESSAGE);
        its_cookie_type =
                static_cast<uint8_t>(MAGIC_COOKIE_CLIENT_MESSAGE_TYPE);
    }

    do {
        its_offset++; // --> first loop has "its_offset = 0"
        if (_size > its_offset + 16) {
            is_found = (_buffer[its_offset] == 0xFF
                     && _buffer[its_offset + 1] == 0xFF
                     && _buffer[its_offset + 2] == its_cookie_identifier
                     && _buffer[its_offset + 3] == 0x00
                     && _buffer[its_offset + 4] == 0x00
                     && _buffer[its_offset + 5] == 0x00
                     && _buffer[its_offset + 6] == 0x00
                     && _buffer[its_offset + 7] == 0x08
                     && _buffer[its_offset + 8] == 0xDE
                     && _buffer[its_offset + 9] == 0xAD
                     && _buffer[its_offset + 10] == 0xBE
                     && _buffer[its_offset + 11] == 0xEF
                     && _buffer[its_offset + 12] == 0x01
                     && _buffer[its_offset + 13] == 0x01
                     && _buffer[its_offset + 14] == its_cookie_type
                     && _buffer[its_offset + 15] == 0x00);
        } else {
            break;
        }

    } while (!is_found);

    return (is_found ? its_offset : 0xFFFFFFFF);
}

template<typename Protocol>
void endpoint_impl<Protocol>::add_default_target(
        service_t, const std::string &, uint16_t) {
}

template<typename Protocol>
void endpoint_impl<Protocol>::remove_default_target(service_t) {
}

template<typename Protocol>
void endpoint_impl<Protocol>::remove_stop_handler(service_t) {
}

template<typename Protocol>
void endpoint_impl<Protocol>::register_error_handler(const error_handler_t &_error_handler) {
    std::lock_guard<std::mutex> its_lock(error_handler_mutex_);
    this->error_handler_ = _error_handler;
}

template<typename Protocol>
instance_t endpoint_impl<Protocol>::get_instance(service_t _service) {

    instance_t its_instance(0xFFFF);

    auto its_host = endpoint_host_.lock();
    if (its_host)
        its_instance = its_host->find_instance(_service, this);

    return its_instance;
}

// Instantiate template
#if defined(__linux__) || defined(__QNX__)
template class endpoint_impl<boost::asio::local::stream_protocol>;
#endif

template class endpoint_impl<boost::asio::ip::tcp>;
template class endpoint_impl<boost::asio::ip::udp>;

} // namespace vsomeip_v3
