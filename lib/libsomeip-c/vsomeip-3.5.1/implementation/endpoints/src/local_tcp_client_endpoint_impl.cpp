// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <iomanip>
#include <sstream>

#include <boost/asio/write.hpp>

#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/endpoint_host.hpp"
#include "../include/local_tcp_client_endpoint_impl.hpp"
#include "../include/local_tcp_server_endpoint_impl.hpp"
#include "../../protocol/include/protocol.hpp"
#include "../../routing/include/routing_host.hpp"

namespace vsomeip_v3 {

local_tcp_client_endpoint_impl::local_tcp_client_endpoint_impl(
        const std::shared_ptr<endpoint_host> &_endpoint_host,
        const std::shared_ptr<routing_host> &_routing_host,
        const endpoint_type & _local,
        const endpoint_type &_remote,
        boost::asio::io_context &_io,
        const std::shared_ptr<configuration> &_configuration)
    : local_tcp_client_endpoint_base_impl(_endpoint_host, _routing_host, _local, _remote, _io,
                                          _configuration),
            recv_buffer_(VSOMEIP_LOCAL_CLIENT_ENDPOINT_RECV_BUFFER_SIZE, 0) {

    is_supporting_magic_cookies_ = false;

    this->max_message_size_ = _configuration->get_max_message_size_local();
    this->queue_limit_ = _configuration->get_endpoint_queue_limit_local();
}

bool local_tcp_client_endpoint_impl::is_local() const {
    return true;
}

void local_tcp_client_endpoint_impl::restart(bool _force) {

    if (!_force && state_ == cei_state_e::CONNECTING) {
        return;
    }
    state_ = cei_state_e::CONNECTING;
    {
        std::lock_guard<std::recursive_mutex> its_lock(mutex_);
        sending_blocked_ = false;
        queue_.clear();
        queue_size_ = 0;
    }
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        shutdown_and_close_socket_unlocked(true);
    }
    was_not_connected_ = true;
    reconnect_counter_ = 0;
    start_connect_timer();
}

void local_tcp_client_endpoint_impl::start() {
    if (state_ == cei_state_e::CLOSED) {
        {
            std::lock_guard<std::recursive_mutex> its_lock(mutex_);
            sending_blocked_ = false;
        }
        connect();
    }
}

void local_tcp_client_endpoint_impl::stop() {
    {
        std::lock_guard<std::recursive_mutex> its_lock(mutex_);
        sending_blocked_ = true;
    }
    {
        std::lock_guard<std::mutex> its_lock(connect_timer_mutex_);
        boost::system::error_code ec;
        connect_timer_.cancel(ec);
    }
    connect_timeout_ = VSOMEIP_DEFAULT_CONNECT_TIMEOUT;

    bool is_open(false);
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        is_open = socket_->is_open();
    }
    if (is_open) {
        bool send_queue_empty(false);
        std::uint32_t times_slept(0);

        while (times_slept <= 50) {
            mutex_.lock();
            send_queue_empty = (queue_.size() == 0);
            mutex_.unlock();
            if (send_queue_empty) {
                break;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                times_slept++;
            }
        }
    }
    shutdown_and_close_socket(false);
}

void local_tcp_client_endpoint_impl::connect() {
    boost::system::error_code its_connect_error;
    std::unique_lock<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code its_error;
    socket_->open(remote_.protocol(), its_error);
    if (!its_error || its_error == boost::asio::error::already_open) {
        // Nagle algorithm off
        socket_->set_option(boost::asio::ip::tcp::no_delay(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "ltcei::connect: couldn't disable "
                            << "Nagle algorithm: " << its_error.message()
                            << " remote:" << remote_.port()
                            << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
        }
        socket_->set_option(boost::asio::socket_base::keep_alive(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "ltcei::connect: couldn't enable "
                            << "keep_alive: " << its_error.message()
                            << " remote:" << remote_.port()
                            << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
        }
        // Setting the TIME_WAIT to 0 seconds forces RST to always be sent in reponse to a FIN
        // Since this is endpoint for internal communication, setting the TIME_WAIT to 5 seconds
        // should be enough to ensure the ACK to the FIN arrives to the server endpoint.
        socket_->set_option(boost::asio::socket_base::linger(true, 5), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "ltcei::connect: couldn't enable "
                    << "SO_LINGER: " << its_error.message()
                    << " remote:" << remote_.port()
                    << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
        }
        socket_->set_option(boost::asio::socket_base::reuse_address(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "ltcei::" << __func__
                            << ": Cannot enable SO_REUSEADDR" << "(" << its_error.message() << ")"
                            << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
        }
        socket_->bind(local_, its_error);
        if (its_error) {
            VSOMEIP_WARNING << "ltcei::" << __func__
                            << ": Cannot bind to client port " << local_.port() << "("
                            << its_error.message() << ")"
                            << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
            try {
                strand_.post(
                    std::bind(&client_endpoint_impl::connect_cbk, shared_from_this(),
                            its_connect_error));
            } catch (const std::exception &e) {
                VSOMEIP_ERROR << "ltcei::connect: " << e.what()
                              << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
            }
            return;
        }
        state_ = cei_state_e::CONNECTING;
        start_connecting_timer();
        socket_->async_connect(
            remote_,
            strand_.wrap(
                std::bind(
                    &local_tcp_client_endpoint_impl::cancel_and_connect_cbk,
                    shared_from_this(),
                    std::placeholders::_1
                )
            )
        );
    } else {
        VSOMEIP_WARNING << "ltcei::connect: Error opening socket: "
                << its_error.message() << " (" << std::dec << its_error.value() << ")"
                << " endpoint > " << this;
        its_connect_error = its_error;
        try {
            strand_.post(
                std::bind(&client_endpoint_impl::connect_cbk, shared_from_this(),
                        its_connect_error));
        } catch (const std::exception &e) {
            VSOMEIP_ERROR << "ltcei::connect: " << e.what()
                          << " endpoint > " << this;
        }
    }
}

void local_tcp_client_endpoint_impl::receive() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if (socket_->is_open()) {
        socket_->async_receive(
            boost::asio::buffer(recv_buffer_),
            strand_.wrap(
                std::bind(
                    &local_tcp_client_endpoint_impl::receive_cbk,
                    std::dynamic_pointer_cast<
                        local_tcp_client_endpoint_impl
                    >(shared_from_this()),
                    std::placeholders::_1,
                    std::placeholders::_2
                )
            )
        );
    }
}

// this overrides client_endpoint_impl::send to disable the pull method
// for local communication
bool local_tcp_client_endpoint_impl::send(const uint8_t *_data, uint32_t _size) {
    std::lock_guard<std::recursive_mutex> its_lock(mutex_);
    bool ret(true);
    if (endpoint_impl::sending_blocked_ ||
        check_message_size(nullptr, _size) != cms_ret_e::MSG_OK ||
        !check_packetizer_space(_size) ||
        !check_queue_limit(_data, _size)) {
        ret = false;
    } else {
#if 0
        std::stringstream msg;
        msg << "lce::send: ";
        for (uint32_t i = 0; i < _size; i++)
            msg << std::hex << std::setw(2) << std::setfill('0')
                << (int)_data[i] << " ";
        VSOMEIP_INFO << msg.str();
#endif
        train_->buffer_->insert(train_->buffer_->end(), _data, _data + _size);
        queue_train(train_);
        train_->buffer_ = std::make_shared<message_buffer_t>();
    }
    return ret;
}

void local_tcp_client_endpoint_impl::send_queued(std::pair<message_buffer_ptr_t, uint32_t> &_entry) {

    static const byte_t its_start_tag[] = { 0x67, 0x37, 0x6D, 0x07 };
    static const byte_t its_end_tag[] = { 0x07, 0x6D, 0x37, 0x67 };
    std::vector<boost::asio::const_buffer> bufs;

    bufs.push_back(boost::asio::buffer(its_start_tag));
    bufs.push_back(boost::asio::buffer(*_entry.first));
    bufs.push_back(boost::asio::buffer(its_end_tag));

    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        boost::asio::async_write(
            *socket_,
            bufs,
            std::bind(
                &client_endpoint_impl::send_cbk,
                std::dynamic_pointer_cast<
                    local_tcp_client_endpoint_impl
                >(shared_from_this()),
                std::placeholders::_1,
                std::placeholders::_2,
                _entry.first
            )
        );
    }
}

void local_tcp_client_endpoint_impl::get_configured_times_from_endpoint(
        service_t _service, method_t _method,
        std::chrono::nanoseconds *_debouncing,
        std::chrono::nanoseconds *_maximum_retention) const {

    (void)_service;
    (void)_method;
    (void)_debouncing;
    (void)_maximum_retention;
    VSOMEIP_ERROR << "ltcei::get_configured_times_from_endpoint called." << " endpoint > " << this;
}

void local_tcp_client_endpoint_impl::send_magic_cookie() {

}

void local_tcp_client_endpoint_impl::receive_cbk(
        boost::system::error_code const &_error, std::size_t _bytes) {

    if (_error) {
        VSOMEIP_INFO << "ltcei::" << __func__ << " Error: " << _error.message()
                     << " endpoint > " << this << " state_ > " << static_cast<int>(state_.load());
        if (_error == boost::asio::error::operation_aborted) {
            // endpoint was stopped
            return;
        } else if (_error == boost::asio::error::eof) {
            std::scoped_lock its_lock {mutex_};
            sending_blocked_ = false;
            queue_.clear();
            queue_size_ = 0;
        } else if (_error == boost::asio::error::connection_reset
                   || _error == boost::asio::error::bad_descriptor) {
            restart(true);
            return;
        }
        error_handler_t handler;
        {
            std::lock_guard<std::mutex> its_lock(error_handler_mutex_);
            handler = error_handler_;
        }
        if (handler)
            handler();
    } else {

#if 0
        std::stringstream msg;
        msg << "lce<" << this << ">::recv: ";
        for (std::size_t i = 0; i < recv_buffer_.size(); i++)
            msg << std::setw(2) << std::setfill('0') << std::hex
                << (int)recv_buffer_[i] << " ";
        VSOMEIP_INFO << msg.str();
#endif

        // We only handle a single message here. Check whether the message
        // format matches what we do expect.
        // TODO: Replace the magic numbers.
        if (_bytes == VSOMEIP_LOCAL_CLIENT_ENDPOINT_RECV_BUFFER_SIZE
                && recv_buffer_[0] == 0x67 && recv_buffer_[1] == 0x37
                && recv_buffer_[2] == 0x6d && recv_buffer_[3] == 0x07
                && recv_buffer_[4] == byte_t(protocol::id_e::ASSIGN_CLIENT_ACK_ID)
                && recv_buffer_[15] == 0x07 && recv_buffer_[16] == 0x6d
                && recv_buffer_[17] == 0x37 && recv_buffer_[18] == 0x67) {

            auto its_routing_host = routing_host_.lock();
            if (its_routing_host)
                its_routing_host->on_message(&recv_buffer_[4],
                        static_cast<length_t>(recv_buffer_.size() - 8), this);
        }

        receive();
    }
}

std::uint16_t local_tcp_client_endpoint_impl::get_local_port() const {

    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if (socket_->is_open()) {
        boost::system::error_code its_error;
        endpoint_type its_local = socket_->local_endpoint(its_error);
        if (!its_error)
            return its_local.port();
    }

    return local_.port();
}

void local_tcp_client_endpoint_impl::set_local_port() {
    // local_port_ is set to zero in ctor of client_endpoint_impl -> do nothing
}

void local_tcp_client_endpoint_impl::print_status() {

    std::string its_path("");
    std::size_t its_data_size(0);
    std::size_t its_queue_size(0);
    {
        std::lock_guard<std::recursive_mutex> its_lock(mutex_);
        its_queue_size = queue_.size();
        its_data_size = queue_size_;
    }

    VSOMEIP_INFO << "status lce: " << its_path  << " queue: "
            << its_queue_size << " data: " << its_data_size;
}

std::string local_tcp_client_endpoint_impl::get_remote_information() const {

    boost::system::error_code ec;
    return remote_.address().to_string(ec) + ":"
            + std::to_string(remote_.port());
}


bool local_tcp_client_endpoint_impl::check_packetizer_space(std::uint32_t _size) {
    if (train_->buffer_->size() + _size < train_->buffer_->size()) {
        VSOMEIP_ERROR << "ltcei: Overflow in packetizer addition ~> abort sending!"
                      << " endpoint > " << this;
        return false;
    }
    if (train_->buffer_->size() + _size > max_message_size_
            && !train_->buffer_->empty()) {
        queue_.push_back(std::make_pair(train_->buffer_, 0));
        queue_size_ += train_->buffer_->size();
        train_->buffer_ = std::make_shared<message_buffer_t>();
    }
    return true;
}

bool local_tcp_client_endpoint_impl::is_reliable() const {

    return true;
}

std::uint32_t local_tcp_client_endpoint_impl::get_max_allowed_reconnects() const {

    return MAX_RECONNECTS_UNLIMITED;
}

void local_tcp_client_endpoint_impl::max_allowed_reconnects_reached() {

    VSOMEIP_ERROR << "ltcei::max_allowed_reconnects_reached: "
            << get_remote_information()
            << " endpoint > " << this;
    error_handler_t handler;
    {
        std::lock_guard<std::mutex> its_lock(error_handler_mutex_);
        handler = error_handler_;
    }
    if (handler)
        handler();
}

} // namespace vsomeip_v3
