// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>
#include <iomanip>

#include <boost/asio/write.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/endpoint_host.hpp"
#include "../../routing/include/routing_host.hpp"
#include "../include/tcp_client_endpoint_impl.hpp"
#include "../../utility/include/utility.hpp"
#include "../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {

tcp_client_endpoint_impl::tcp_client_endpoint_impl(
        const std::shared_ptr<endpoint_host>& _endpoint_host,
        const std::shared_ptr<routing_host>& _routing_host,
        const endpoint_type& _local,
        const endpoint_type& _remote,
        boost::asio::io_context &_io,
        const std::shared_ptr<configuration>& _configuration)
    : tcp_client_endpoint_base_impl(_endpoint_host, _routing_host, _local, _remote, _io,
                                    _configuration),
      recv_buffer_size_initial_(VSOMEIP_SOMEIP_HEADER_SIZE),
      recv_buffer_(std::make_shared<message_buffer_t>(recv_buffer_size_initial_, 0)),
      shrink_count_(0),
      buffer_shrink_threshold_(configuration_->get_buffer_shrink_threshold()),
      remote_address_(_remote.address()),
      remote_port_(_remote.port()),
      last_cookie_sent_(std::chrono::steady_clock::now() - std::chrono::seconds(11)),
      // send timeout after 2/3 of configured ttl, warning after 1/3
      send_timeout_(configuration_->get_sd_ttl() * 666),
      send_timeout_warning_(send_timeout_ / 2),
      tcp_restart_aborts_max_(configuration_->get_max_tcp_restart_aborts()),
      tcp_connect_time_max_(configuration_->get_max_tcp_connect_time()),
      aborted_restart_count_(0),
      sent_timer_(_io) {

    is_supporting_magic_cookies_ = true;

    this->max_message_size_ = _configuration->get_max_message_size_reliable(
                                                      _remote.address().to_string(),
                                                      _remote.port());
    this->queue_limit_ = _configuration->get_endpoint_queue_limit(_remote.address().to_string(),
                                                                  _remote.port());
}

tcp_client_endpoint_impl::~tcp_client_endpoint_impl() {
    std::shared_ptr<endpoint_host> its_host = endpoint_host_.lock();
    if (its_host) {
        its_host->release_port(local_.port(), true);
    }
}

bool tcp_client_endpoint_impl::is_local() const {
    return false;
}

void tcp_client_endpoint_impl::start() {
    strand_.dispatch(std::bind(&client_endpoint_impl::connect,
        this->shared_from_this()));
}

void tcp_client_endpoint_impl::restart(bool _force) {
    auto self = std::dynamic_pointer_cast< tcp_client_endpoint_impl >(shared_from_this());
    auto restart_func = [self, _force] {
        if (!_force && self->state_ == cei_state_e::CONNECTING) {
            std::chrono::steady_clock::time_point its_current
                = std::chrono::steady_clock::now();
            std::int64_t its_connect_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    its_current - self->connect_timepoint_).count();
            if (self->aborted_restart_count_ < self->tcp_restart_aborts_max_
                    && its_connect_duration < self->tcp_connect_time_max_) {
                self->aborted_restart_count_++;
                return;
            } else {
                VSOMEIP_WARNING << "tce::restart: maximum number of aborted restarts ["
                        << self->tcp_restart_aborts_max_ << "] reached! its_connect_duration: "
                        << its_connect_duration;
            }
        }
        self->state_ = cei_state_e::CONNECTING;
        std::string address_port_local;
        {
            std::lock_guard<std::mutex> its_lock(self->socket_mutex_);
            address_port_local = self->get_address_port_local();
            self->shutdown_and_close_socket_unlocked(true);
            self->recv_buffer_ = std::make_shared<message_buffer_t>(self->recv_buffer_size_initial_, 0);
        }
        self->was_not_connected_ = true;
        self->reconnect_counter_ = 0;
        {
            std::lock_guard<std::recursive_mutex> its_lock(self->mutex_);
            for (const auto &q : self->queue_) {
                const service_t its_service = bithelper::read_uint16_be(&(*q.first)[VSOMEIP_SERVICE_POS_MIN]);
                const method_t its_method   = bithelper::read_uint16_be(&(*q.first)[VSOMEIP_METHOD_POS_MIN]);
                const client_t its_client   = bithelper::read_uint16_be(&(*q.first)[VSOMEIP_CLIENT_POS_MIN]);
                const session_t its_session = bithelper::read_uint16_be(&(*q.first)[VSOMEIP_SESSION_POS_MIN]);
                VSOMEIP_WARNING << "tce::restart: dropping message: "
                        << "remote:" << self->get_address_port_remote() << " ("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << its_client << "): ["
                        << std::setw(4) << its_service << "."
                        << std::setw(4) << its_method << "."
                        << std::setw(4) << its_session << "]"
                        << " size: " << std::dec << q.first->size();
            }
            self->queue_.clear();
            self->queue_size_ = 0;
        }
        VSOMEIP_WARNING << "tce::restart: local: " << address_port_local
                << " remote: " << self->get_address_port_remote();
        self->start_connect_timer();
    };
    // bind to strand_ to avoid socket closure if
    // parallel socket operation is currently active
    strand_.dispatch(restart_func);
}

void tcp_client_endpoint_impl::connect() {
    start_connecting_timer();
    std::unique_lock<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code its_error;
    socket_->open(remote_.protocol(), its_error);

    if (!its_error || its_error == boost::asio::error::already_open) {
        // Nagle algorithm off
        socket_->set_option(boost::asio::ip::tcp::no_delay(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tcp_client_endpoint::connect: couldn't disable "
                    << "Nagle algorithm: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }

        socket_->set_option(boost::asio::socket_base::keep_alive(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tcp_client_endpoint::connect: couldn't enable "
                    << "keep_alive: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }

        // Enable SO_REUSEADDR to avoid bind problems with services going offline
        // and coming online again and the user has specified only a small number
        // of ports in the clients section for one service instance
        socket_->set_option(boost::asio::socket_base::reuse_address(true), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tcp_client_endpoint::connect: couldn't enable "
                    << "SO_REUSEADDR: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }
        socket_->set_option(boost::asio::socket_base::linger(true, 0), its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tcp_client_endpoint::connect: couldn't enable "
                    << "SO_LINGER: " << its_error.message()
                    << " remote:" << get_address_port_remote();
        }

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
        // If specified, bind to device
        std::string its_device(configuration_->get_device());
        if (its_device != "") {
            if (setsockopt(socket_->native_handle(),
                    SOL_SOCKET, SO_BINDTODEVICE, its_device.c_str(), static_cast<socklen_t>(its_device.size())) == -1) {
                VSOMEIP_WARNING << "TCP Client: Could not bind to device \"" << its_device << "\"";
            }
        }
#endif

        // In case a client endpoint port was configured,
        // bind to it before connecting
        if (local_.port() != ILLEGAL_PORT) {
            boost::system::error_code its_bind_error;
            socket_->bind(local_, its_bind_error);
            if(its_bind_error) {
                VSOMEIP_WARNING << "tcp_client_endpoint::connect: "
                        "Error binding socket: " << its_bind_error.message()
                        << " local: " << get_address_port_local()
                        << " remote:" << get_address_port_remote();

                its_lock.unlock();

                std::shared_ptr<endpoint_host> its_host = endpoint_host_.lock();
                if (its_host) {
                    // set new client port depending on service / instance / remote port
                    if (!its_host->on_bind_error(shared_from_this(), remote_address_, remote_port_)) {
                        VSOMEIP_WARNING << "tcp_client_endpoint::connect: "
                                "Failed to set new local port for tce: "
                                << " local: " << local_.address().to_string()
                                << ":" << std::dec << local_.port()
                                << " remote:" << get_address_port_remote();
                    } else {
                        VSOMEIP_INFO << "tcp_client_endpoint::connect: "
                                "Using new new local port for tce: "
                                << " local: " << local_.address().to_string()
                                << ":" << std::dec << local_.port()
                                << " remote:" << get_address_port_remote();
                    }
                }
                std::size_t operations_cancelled;
                {
                    std::lock_guard<std::mutex> its_lock(connecting_timer_mutex_);
                    operations_cancelled = connecting_timer_.cancel();
                }
                if (operations_cancelled != 0) {
                    try {
                        VSOMEIP_WARNING
                                << "tce::" << __func__
                                << ":connecting to: local:" << this->get_address_port_local()
                                << " remote: " << this->get_address_port_remote();
                        // don't connect on bind error to avoid using a random port
                        strand_.post(std::bind(&client_endpoint_impl::connect_cbk,
                                        shared_from_this(), its_bind_error));
                    } catch (const std::exception &e) {
                        VSOMEIP_ERROR << "tcp_client_endpoint_impl::connect: "
                                << e.what()
                                << " local: " << get_address_port_local()
                                << " remote:" << get_address_port_remote();
                    }
                }
                return;
            }
        }
        state_ = cei_state_e::CONNECTING;
        connect_timepoint_ = std::chrono::steady_clock::now();
        aborted_restart_count_ = 0;
        VSOMEIP_WARNING << "tce::" << __func__
                        << ":connecting to: local:" << this->get_address_port_local()
                        << " remote: " << this->get_address_port_remote();
        socket_->async_connect(
            remote_,
            strand_.wrap(
                std::bind(
                    &tcp_client_endpoint_base_impl::cancel_and_connect_cbk,
                    shared_from_this(),
                    std::placeholders::_1
                )
            )
        );
    } else {
        VSOMEIP_WARNING << "tce::" << __func__ << ": could not connect "
                        << "(" << its_error.value() << "): " << its_error.message();
        std::size_t operations_cancelled;
        {
            std::lock_guard<std::mutex> its_lock(connecting_timer_mutex_);
            operations_cancelled = connecting_timer_.cancel();
        }
        if (operations_cancelled != 0) {
            VSOMEIP_WARNING << "tce::" << __func__  << "Error opening socket: (" << its_error.message()
                            << "): conneting to local:"  << this->get_address_port_local()
                            << " remote: " << this->get_address_port_remote();
            strand_.post(std::bind(&tcp_client_endpoint_base_impl::connect_cbk,
                                    shared_from_this(), its_error));
        }
    }
}

void tcp_client_endpoint_impl::receive() {
    message_buffer_ptr_t its_recv_buffer;
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        its_recv_buffer = recv_buffer_;
    }
    auto self = std::dynamic_pointer_cast< tcp_client_endpoint_impl >(shared_from_this());
    strand_.dispatch([self, &its_recv_buffer](){
        self->receive(its_recv_buffer, 0, 0);
    });
}

void tcp_client_endpoint_impl::receive(message_buffer_ptr_t  _recv_buffer,
             std::size_t _recv_buffer_size,
             std::size_t _missing_capacity) {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if(socket_->is_open()) {
        const std::size_t its_capacity(_recv_buffer->capacity());
        size_t buffer_size = its_capacity - _recv_buffer_size;
        try {
            if (_missing_capacity) {
                if (_missing_capacity > MESSAGE_SIZE_UNLIMITED) {
                    VSOMEIP_ERROR << "Missing receive buffer capacity exceeds allowed maximum!";
                    return;
                }
                const std::size_t its_required_capacity(_recv_buffer_size + _missing_capacity);
                if (its_capacity < its_required_capacity) {
                    _recv_buffer->reserve(its_required_capacity);
                    _recv_buffer->resize(its_required_capacity, 0x0);
                    if (_recv_buffer->size() > 1048576) {
                        VSOMEIP_INFO << "tce: recv_buffer size is: " <<
                                _recv_buffer->size()
                                << " local: " << get_address_port_local()
                                << " remote: " << get_address_port_remote();
                    }
                }
                buffer_size = _missing_capacity;
            } else if (buffer_shrink_threshold_
                    && shrink_count_ > buffer_shrink_threshold_
                    && _recv_buffer_size == 0) {
                _recv_buffer->resize(recv_buffer_size_initial_, 0x0);
                _recv_buffer->shrink_to_fit();
                buffer_size = recv_buffer_size_initial_;
                shrink_count_ = 0;
            }
        } catch (const std::exception &e) {
            handle_recv_buffer_exception(e, _recv_buffer, _recv_buffer_size);
            // don't start receiving again
            return;
        }
        socket_->async_receive(
            boost::asio::buffer(&(*_recv_buffer)[_recv_buffer_size], buffer_size),
            strand_.wrap(
                std::bind(
                    &tcp_client_endpoint_impl::receive_cbk,
                    std::dynamic_pointer_cast< tcp_client_endpoint_impl >(shared_from_this()),
                    std::placeholders::_1,
                    std::placeholders::_2,
                    _recv_buffer,
                    _recv_buffer_size
                )
            )
        );
    }
}

void tcp_client_endpoint_impl::send_queued(std::pair<message_buffer_ptr_t, uint32_t> &_entry) {
    const service_t its_service = bithelper::read_uint16_be(&(*_entry.first)[VSOMEIP_SERVICE_POS_MIN]);
    const method_t its_method   = bithelper::read_uint16_be(&(*_entry.first)[VSOMEIP_METHOD_POS_MIN]);
    const client_t its_client   = bithelper::read_uint16_be(&(*_entry.first)[VSOMEIP_CLIENT_POS_MIN]);
    const session_t its_session = bithelper::read_uint16_be(&(*_entry.first)[VSOMEIP_SESSION_POS_MIN]);
    if (has_enabled_magic_cookies_) {
        const std::chrono::steady_clock::time_point now =
                std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_cookie_sent_) > std::chrono::milliseconds(10000)) {
            send_magic_cookie(_entry.first);
            last_cookie_sent_ = now;
        }
    }


#if 0
    std::stringstream msg;
    msg << "tcei<" << remote_.address() << ":"
        << std::dec << remote_.port()  << ">::sq: ";
    for (std::size_t i = 0; i < _buffer->size(); i++)
        msg << std::hex << std::setw(2) << std::setfill('0')
            << (int)(*_entry.first)[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        if (socket_->is_open()) {
            boost::asio::async_write(
                *socket_,
                boost::asio::buffer(*_entry.first),
                std::bind(
                    &tcp_client_endpoint_impl::write_completion_condition,
                    std::static_pointer_cast<tcp_client_endpoint_impl>(shared_from_this()),
                    std::placeholders::_1,
                    std::placeholders::_2,
                    _entry.first->size(),
                    its_service, its_method, its_client, its_session,
                    std::chrono::steady_clock::now()),
                strand_.wrap(
                    std::bind(
                    &tcp_client_endpoint_base_impl::send_cbk,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2,
                    _entry.first
                ))
            );
        }
    }
}

void tcp_client_endpoint_impl::get_configured_times_from_endpoint(
        service_t _service, method_t _method,
        std::chrono::nanoseconds *_debouncing,
        std::chrono::nanoseconds *_maximum_retention) const {
    configuration_->get_configured_timing_requests(_service,
            remote_address_.to_string(), remote_port_, _method,
            _debouncing, _maximum_retention);
}

bool tcp_client_endpoint_impl::get_remote_address(
        boost::asio::ip::address &_address) const {
    if (remote_address_.is_unspecified()) {
        return false;
    }
    _address = remote_address_;
    return true;
}

uint16_t tcp_client_endpoint_impl::get_local_port() const {

    uint16_t its_port(0);

    // Local port may be zero, if no client ports are configured
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if (socket_->is_open()) {
        boost::system::error_code its_error;
        endpoint_type its_local = socket_->local_endpoint(its_error);
        if (!its_error) {
            its_port = its_local.port();
            return its_port;
        } else {
            VSOMEIP_WARNING << "tce::" << __func__ << ": couldn't get local endpoint port "
                            << "(" << its_error.value() << "): " << its_error.message();
        }
    }

    return local_.port();
}

void tcp_client_endpoint_impl::set_local_port() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    boost::system::error_code its_error;
    if (socket_->is_open()) {
        endpoint_type its_endpoint = socket_->local_endpoint(its_error);
        if (!its_error) {
            local_.port(its_endpoint.port());
        } else {
            VSOMEIP_WARNING << "tcp_client_endpoint_impl::set_local_port() "
                            << " couldn't get local_endpoint: " << its_error.message();
        }
    } else {
        VSOMEIP_WARNING << "tcp_client_endpoint_impl::set_local_port() "
                        << "failed to set port because the socket is not opened";
    }
}

void tcp_client_endpoint_impl::set_local_port(port_t _port) {

    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if (!socket_->is_open()) {
        local_.port(_port);
    } else {
        boost::system::error_code its_error;
        endpoint_type its_endpoint = socket_->local_endpoint(its_error);
        if (!its_error)
            local_.port(its_endpoint.port());
        VSOMEIP_ERROR << "tcp_client_endpoint_impl::set_local_port() "
                      << "Cannot change port on open socket!";
    }
}

std::size_t tcp_client_endpoint_impl::write_completion_condition(
        const boost::system::error_code& _error, std::size_t _bytes_transferred,
        std::size_t _bytes_to_send, service_t _service, method_t _method,
        client_t _client, session_t _session,
        const std::chrono::steady_clock::time_point _start) {

    if (_error) {
        VSOMEIP_ERROR << "tce::write_completion_condition: "
                << _error.message() << "(" << std::dec << _error.value()
                << ") bytes transferred: " << std::dec << _bytes_transferred
                << " bytes to sent: " << std::dec << _bytes_to_send << " "
                << "remote:" << get_address_port_remote() << " ("
                << std::hex << std::setfill('0')
                << std::setw(4) << _client << "): ["
                << std::setw(4) << _service << "."
                << std::setw(4) << _method << "."
                << std::setw(4) << _session << "]";
        return 0;
    }

    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    const std::chrono::milliseconds passed = std::chrono::duration_cast<std::chrono::milliseconds>(now - _start);
    if (passed > send_timeout_warning_) {
        if (passed > send_timeout_) {
            VSOMEIP_ERROR << "tce::write_completion_condition: "
                    << _error.message() << "(" << std::dec << _error.value()
                    << ") took longer than " << std::dec << send_timeout_.count()
                    << "ms bytes transferred: " << std::dec << _bytes_transferred
                    << " bytes to sent: " << std::dec << _bytes_to_send << " "
                    << "remote:" << get_address_port_remote() << " ("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _client << "): ["
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _method << "."
                    << std::setw(4) << _session << "]";
        } else {
            VSOMEIP_WARNING << "tce::write_completion_condition: "
                    << _error.message() << "(" << std::dec << _error.value()
                    << ") took longer than " << std::dec << send_timeout_warning_.count()
                    << "ms bytes transferred: " << std::dec << _bytes_transferred
                    << " bytes to sent: " << std::dec << _bytes_to_send << " "
                    << "remote:" << get_address_port_remote() << " ("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _client << "): ["
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _method << "."
                    << std::setw(4) << _session << "]";
        }
    }
    return _bytes_to_send - _bytes_transferred;
}

std::uint16_t tcp_client_endpoint_impl::get_remote_port() const {
    return remote_port_;
}

bool tcp_client_endpoint_impl::is_reliable() const {
  return true;
}

bool tcp_client_endpoint_impl::is_magic_cookie(const message_buffer_ptr_t& _recv_buffer,
                                               size_t _offset) const {
    return (0 == std::memcmp(SERVICE_COOKIE, &(*_recv_buffer)[_offset], sizeof(SERVICE_COOKIE)));
}

void tcp_client_endpoint_impl::send_magic_cookie(message_buffer_ptr_t &_buffer) {
    if (max_message_size_ == MESSAGE_SIZE_UNLIMITED
            || max_message_size_ - _buffer->size() >=
        VSOMEIP_SOMEIP_HEADER_SIZE + VSOMEIP_SOMEIP_MAGIC_COOKIE_SIZE) {
        _buffer->insert(
            _buffer->begin(),
            CLIENT_COOKIE,
            CLIENT_COOKIE + sizeof(CLIENT_COOKIE)
        );
        queue_size_ += sizeof(CLIENT_COOKIE);
    } else {
        VSOMEIP_WARNING << "Packet full. Cannot insert magic cookie!";
    }
}

void tcp_client_endpoint_impl::receive_cbk(
        boost::system::error_code const &_error, std::size_t _bytes,
        const message_buffer_ptr_t& _recv_buffer, std::size_t _recv_buffer_size) {
    if (_error == boost::asio::error::operation_aborted) {
        // endpoint was stopped
        return;
    }
#if 0
    std::stringstream msg;
    msg << "cei::rcb (" << _error.message() << "): ";
    for (std::size_t i = 0; i < _bytes + _recv_buffer_size; ++i)
        msg << std::hex << std::setw(2) << std::setfill('0')
            << (int) (_recv_buffer)[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    std::unique_lock<std::mutex> its_lock(socket_mutex_);
    std::shared_ptr<routing_host> its_host = routing_host_.lock();
    if (its_host) {
        std::uint32_t its_missing_capacity(0);
        if (!_error && 0 < _bytes) {
            if (_recv_buffer_size + _bytes > _recv_buffer->size()) {
                VSOMEIP_ERROR << "receive buffer overflow in tcp client endpoint ~> abort!";
                return;
            }
            _recv_buffer_size += _bytes;

            size_t its_iteration_gap = 0;
            bool has_full_message(false);
            do {
                uint64_t read_message_size
                    = utility::get_message_size(&(*_recv_buffer)[its_iteration_gap],
                            _recv_buffer_size);
                if (read_message_size > MESSAGE_SIZE_UNLIMITED) {
                    VSOMEIP_ERROR << "Message size exceeds allowed maximum!";
                    return;
                }
                uint32_t current_message_size = static_cast<uint32_t>(read_message_size);
                has_full_message = (current_message_size > VSOMEIP_RETURN_CODE_POS
                                 && current_message_size <= _recv_buffer_size);
                if (has_full_message) {
                    bool needs_forwarding(true);
                    if (is_magic_cookie(_recv_buffer, its_iteration_gap)) {
                        has_enabled_magic_cookies_ = true;
                    } else {
                        if (has_enabled_magic_cookies_) {
                            uint32_t its_offset = find_magic_cookie(&(*_recv_buffer)[its_iteration_gap],
                                    (uint32_t) _recv_buffer_size);
                            if (its_offset < current_message_size) {
                                VSOMEIP_ERROR << "Message includes Magic Cookie. Ignoring it.";
                                current_message_size = its_offset;
                                needs_forwarding = false;
                            }
                        }
                    }
                    if (needs_forwarding) {
                        if (!has_enabled_magic_cookies_) {
                            its_lock.unlock();
                            its_host->on_message(&(*_recv_buffer)[its_iteration_gap],
                                                 current_message_size, this,
                                                 false,
                                                 VSOMEIP_ROUTING_CLIENT,
                                                 nullptr,
                                                 remote_address_,
                                                 remote_port_);
                            its_lock.lock();
                        } else {
                            // Only call on_message without a magic cookie in front of the buffer!
                            if (!is_magic_cookie(_recv_buffer, its_iteration_gap)) {
                                its_lock.unlock();
                                its_host->on_message(&(*_recv_buffer)[its_iteration_gap],
                                                     current_message_size, this,
                                                     false,
                                                     VSOMEIP_ROUTING_CLIENT,
                                                     nullptr,
                                                     remote_address_,
                                                     remote_port_);
                                its_lock.lock();
                            }
                        }
                    }
                    calculate_shrink_count(_recv_buffer, _recv_buffer_size);
                    _recv_buffer_size -= current_message_size;
                    its_iteration_gap += current_message_size;
                    its_missing_capacity = 0;
                } else if (has_enabled_magic_cookies_ && _recv_buffer_size > 0) {
                    const uint32_t its_offset = find_magic_cookie(
                            &(*_recv_buffer)[its_iteration_gap], _recv_buffer_size);
                    if (its_offset < _recv_buffer_size) {
                        _recv_buffer_size -= its_offset;
                        its_iteration_gap += its_offset;
                        has_full_message = true; // trigger next loop
                        VSOMEIP_ERROR << "Detected Magic Cookie within message data."
                            << " Resyncing. local: " << get_address_port_local()
                            << " remote: " << get_address_port_remote();
                    }
                }

                if (!has_full_message) {
                    if (_recv_buffer_size > VSOMEIP_RETURN_CODE_POS) {
                        bool invalid_parameter_detected { false };
                        if (recv_buffer_->size() <= (its_iteration_gap + VSOMEIP_RETURN_CODE_POS)) {
                            VSOMEIP_ERROR << "TCP Client receive_cbk is trying to access invalid vector position."
                            << " Actual: " << recv_buffer_->size()
                            << " Received: " << _recv_buffer->size()
                            << " Current: " << current_message_size
                            << " Indicated: " << _recv_buffer_size
                            << " Bytes: " << _bytes
                            << " Iteration_gap: " << its_iteration_gap
                            << " Is_full_message: " << has_full_message;
                            return;
                        } else if ((*recv_buffer_)[its_iteration_gap + VSOMEIP_PROTOCOL_VERSION_POS] != VSOMEIP_PROTOCOL_VERSION) {
                            invalid_parameter_detected = true;
                            VSOMEIP_ERROR << "tce: Wrong protocol version: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t((*recv_buffer_)[its_iteration_gap + VSOMEIP_PROTOCOL_VERSION_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << get_address_port_remote();
                            // ensure to send back a message w/ wrong protocol version
                            its_lock.unlock();
                            its_host->on_message(&(*_recv_buffer)[its_iteration_gap],
                                                 VSOMEIP_SOMEIP_HEADER_SIZE + 8, this,
                                                 false,
                                                 VSOMEIP_ROUTING_CLIENT,
                                                 nullptr,
                                                 remote_address_,
                                                 remote_port_);
                            its_lock.lock();
                        } else if (!utility::is_valid_message_type(static_cast<message_type_e>(
                                (*recv_buffer_)[its_iteration_gap + VSOMEIP_MESSAGE_TYPE_POS]))) {
                            invalid_parameter_detected = true;
                            VSOMEIP_ERROR << "tce: Invalid message type: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t((*recv_buffer_)[its_iteration_gap + VSOMEIP_MESSAGE_TYPE_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << get_address_port_remote();
                        } else if (!utility::is_valid_return_code(static_cast<return_code_e>(
                                (*recv_buffer_)[its_iteration_gap + VSOMEIP_RETURN_CODE_POS]))) {
                            invalid_parameter_detected = true;
                            VSOMEIP_ERROR << "tce: Invalid return code: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t((*recv_buffer_)[its_iteration_gap + VSOMEIP_RETURN_CODE_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << get_address_port_remote();
                        }

                        if (invalid_parameter_detected) {
                            state_ = cei_state_e::CONNECTING;
                            shutdown_and_close_socket_unlocked(false);
                            its_lock.unlock();

                            // wait_until_sent interprets "no error" as timeout.
                            // Therefore call it with an error.
                            wait_until_sent(boost::asio::error::operation_aborted);
                            return;
                        }
                    }
                    if (max_message_size_ != MESSAGE_SIZE_UNLIMITED &&
                            current_message_size > max_message_size_) {
                        _recv_buffer_size = 0;
                        _recv_buffer->resize(recv_buffer_size_initial_, 0x0);
                        _recv_buffer->shrink_to_fit();
                        if (has_enabled_magic_cookies_) {
                            VSOMEIP_ERROR << "Received a TCP message which exceeds "
                                          << "maximum message size ("
                                          << std::dec << current_message_size
                                          << "). Magic Cookies are enabled: "
                                          << "Resetting receiver. local: "
                                          << get_address_port_local() << " remote: "
                                          << get_address_port_remote();
                        } else {
                            VSOMEIP_ERROR << "Received a TCP message which exceeds "
                                          << "maximum message size ("
                                          << std::dec << current_message_size
                                          << ") Magic cookies are disabled, "
                                          << "Restarting connection. "
                                          << "local: " << get_address_port_local()
                                          << " remote: " << get_address_port_remote();
                            state_ = cei_state_e::CONNECTING;
                            shutdown_and_close_socket_unlocked(false);
                            its_lock.unlock();

                            // wait_until_sent interprets "no error" as timeout.
                            // Therefore call it with an error.
                            wait_until_sent(boost::asio::error::operation_aborted);
                            return;
                        }
                    } else if (current_message_size > _recv_buffer_size) {
                            its_missing_capacity = current_message_size
                                    - static_cast<std::uint32_t>(_recv_buffer_size);
                    } else if (VSOMEIP_SOMEIP_HEADER_SIZE > _recv_buffer_size) {
                            its_missing_capacity = VSOMEIP_SOMEIP_HEADER_SIZE
                                    - static_cast<std::uint32_t>(_recv_buffer_size);
                    } else if (has_enabled_magic_cookies_ && _recv_buffer_size > 0) {
                        // no need to check for magic cookie here again: has_full_message
                        // would have been set to true if there was one present in the data
                        _recv_buffer_size = 0;
                        _recv_buffer->resize(recv_buffer_size_initial_, 0x0);
                        _recv_buffer->shrink_to_fit();
                        its_missing_capacity = 0;
                        VSOMEIP_ERROR << "tce::c<" << this
                                << ">rcb: recv_buffer_capacity: "
                                << _recv_buffer->capacity()
                                << " local: " << get_address_port_local()
                                << " remote: " << get_address_port_remote()
                                << ". Didn't find magic cookie in broken data, trying to resync.";
                    } else {
                        VSOMEIP_ERROR << "tce::c<" << this
                                << ">rcb: recv_buffer_size is: " << std::dec
                                << _recv_buffer_size << " but couldn't read "
                                "out message_size. recv_buffer_capacity: "
                                << _recv_buffer->capacity()
                                << " its_iteration_gap: " << its_iteration_gap
                                << " local: " << get_address_port_local()
                                << " remote: " << get_address_port_remote()
                                << ". Restarting connection due to missing/broken data TCP stream.";
                        state_ = cei_state_e::CONNECTING;
                        shutdown_and_close_socket_unlocked(false);
                        its_lock.unlock();

                        // wait_until_sent interprets "no error" as timeout.
                        // Therefore call it with an error.
                        wait_until_sent(boost::asio::error::operation_aborted);
                        return;
                    }
                }
            } while (has_full_message && _recv_buffer_size);
            if (its_iteration_gap) {
                // Copy incomplete message to front for next receive_cbk iteration
                for (size_t i = 0; i < _recv_buffer_size; ++i) {
                    (*_recv_buffer)[i] = (*_recv_buffer)[i + its_iteration_gap];
                }
                // Still more capacity needed after shifting everything to front?
                if (its_missing_capacity &&
                        its_missing_capacity <= _recv_buffer->capacity() - _recv_buffer_size) {
                    its_missing_capacity = 0;
                }
            }
            its_lock.unlock();
            auto self = std::dynamic_pointer_cast< tcp_client_endpoint_impl >(shared_from_this());
            strand_.dispatch([self, &_recv_buffer, _recv_buffer_size, its_missing_capacity](){
                self->receive(_recv_buffer, _recv_buffer_size, its_missing_capacity);
            });
        } else {
            VSOMEIP_WARNING << "tcp_client_endpoint receive_cbk: "
                    << _error.message() << "(" << std::dec << _error.value()
                    << ") local: " << get_address_port_local()
                    << " remote: " << get_address_port_remote();
            if (_error ==  boost::asio::error::eof ||
                    _error == boost::asio::error::timed_out ||
                    _error == boost::asio::error::bad_descriptor ||
                    _error == boost::asio::error::connection_reset) {
                if (state_ == cei_state_e::CONNECTING) {
                    VSOMEIP_WARNING << "tcp_client_endpoint receive_cbk already"
                            " restarting" << get_remote_information();
                } else {
                    VSOMEIP_WARNING << "tcp_client_endpoint receive_cbk restarting.";
                    state_ = cei_state_e::CONNECTING;
                    shutdown_and_close_socket_unlocked(false);
                    its_lock.unlock();

                    // wait_until_sent interprets "no error" as timeout.
                    // Therefore call it with an error.
                    wait_until_sent(boost::asio::error::operation_aborted);
                }
            } else {
                its_lock.unlock();
                auto self = std::dynamic_pointer_cast< tcp_client_endpoint_impl >(shared_from_this());
                strand_.dispatch([self, &_recv_buffer, _recv_buffer_size, its_missing_capacity](){
                    self->receive(_recv_buffer, _recv_buffer_size, its_missing_capacity);
                });
            }
        }
    }
}

void tcp_client_endpoint_impl::calculate_shrink_count(const message_buffer_ptr_t& _recv_buffer,
                                                      std::size_t _recv_buffer_size) {
    if (buffer_shrink_threshold_) {
        if (_recv_buffer->capacity() != recv_buffer_size_initial_) {
            if (_recv_buffer_size < (_recv_buffer->capacity() >> 1)) {
                shrink_count_++;
            } else {
                shrink_count_ = 0;
            }
        }
    }
}


std::string tcp_client_endpoint_impl::get_address_port_remote() const {
    std::string its_address_port;
    its_address_port.reserve(21);
    boost::asio::ip::address its_address;
    if (get_remote_address(its_address)) {
        its_address_port += its_address.to_string();
    }
    its_address_port += ":";
    its_address_port += std::to_string(remote_port_);
    return its_address_port;
}

std::string tcp_client_endpoint_impl::get_address_port_local() const {
    std::string its_address_port;
    its_address_port.reserve(21);
    boost::system::error_code ec;
    if (socket_->is_open()) {
        endpoint_type its_local_endpoint = socket_->local_endpoint(ec);
        if (!ec) {
            its_address_port += its_local_endpoint.address().to_string(ec);
            its_address_port += ":";
            its_address_port.append(std::to_string(its_local_endpoint.port()));
        } else {
            VSOMEIP_WARNING << "tce" << __func__ << "coudn't get local endpoint: (" << ec.value()
                            << "): " << ec.message();
        }
    }
    return its_address_port;
}

void tcp_client_endpoint_impl::handle_recv_buffer_exception(
        const std::exception &_e,
        const message_buffer_ptr_t& _recv_buffer,
        std::size_t _recv_buffer_size) {

    std::stringstream its_message;
    its_message << "tcp_client_endpoint_impl::connection catched exception"
            << _e.what() << " local: " << get_address_port_local()
            << " remote: " << get_address_port_remote()
            << " shutting down connection. Start of buffer: "
            << std::setfill('0') << std::hex;

    for (std::size_t i = 0; i < _recv_buffer_size && i < 16; i++) {
        its_message << std::setw(2) << (int) ((*_recv_buffer)[i]) << " ";
    }

    its_message << " Last 16 Bytes captured: ";
    for (int i = 15; _recv_buffer_size > 15 && i >= 0; i--) {
        its_message << std::setw(2) << (int) ((*_recv_buffer)[static_cast<size_t>(i)]) << " ";
    }
    VSOMEIP_ERROR << its_message.str();
    _recv_buffer->clear();
    {
        std::lock_guard<std::recursive_mutex> its_lock(mutex_);
        sending_blocked_ = true;
    }
    {
        std::lock_guard<std::mutex> its_lock(connect_timer_mutex_);
        boost::system::error_code ec;
        connect_timer_.cancel(ec);
    }
    if (socket_->is_open()) {
        boost::system::error_code its_error;
        socket_->shutdown(socket_type::shutdown_both, its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tce::" << __func__ << ": socket shutdown error "
                            << "(" << its_error.value() << "): " << its_error.message();
        }
        socket_->close(its_error);
        if (its_error) {
            VSOMEIP_WARNING << "tce::" << __func__ << ": socket close error "
                            << "(" << its_error.value() << "): " << its_error.message();
        }
    }
}

void tcp_client_endpoint_impl::print_status() {
    std::size_t its_data_size(0);
    std::size_t its_queue_size(0);
    std::size_t its_receive_buffer_capacity(0);
    {
        std::lock_guard<std::recursive_mutex> its_lock(mutex_);
        its_queue_size = queue_.size();
        its_data_size = queue_size_;
    }
    std::string local;
    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        local = get_address_port_local();
        its_receive_buffer_capacity = recv_buffer_->capacity();
    }

    VSOMEIP_INFO << "status tce: " << local << " -> "
            << get_address_port_remote()
            << " queue: " << std::dec << its_queue_size
            << " data: " << std::dec << its_data_size
            << " recv_buffer: " << std::dec << its_receive_buffer_capacity;
}

std::string tcp_client_endpoint_impl::get_remote_information() const {
    boost::system::error_code ec;
    return remote_.address().to_string(ec) + ":"
            + std::to_string(remote_.port());
}

void tcp_client_endpoint_impl::send_cbk(boost::system::error_code const &_error,
                                        std::size_t _bytes,
                                        const message_buffer_ptr_t& _sent_msg) {
    (void)_bytes;

    std::lock_guard<std::recursive_mutex> its_lock(mutex_);
    boost::system::error_code ec;
    sent_timer_.cancel(ec);

    if (!_error) {
        if (queue_.size() > 0) {
            queue_size_ -= queue_.front().first->size();
            queue_.pop_front();

            update_last_departure();

            if (queue_.empty())
                is_sending_ = false;
            else {
                auto its_entry = get_front();
                if (its_entry.first) {
                    auto self = std::dynamic_pointer_cast< tcp_client_endpoint_impl >(shared_from_this());
                    strand_.dispatch(
                        [self, &its_entry]() { self->send_queued(its_entry);}
                    );
                }
            }
        }
        return;
    } else {
        is_sending_ = false;

        if (_error == boost::system::errc::destination_address_required) {
            VSOMEIP_WARNING << "tce::send_cbk received error: " << _error.message()
                    << " (" << std::dec << _error.value() << ") "
                            << get_remote_information();
            was_not_connected_ = true;
        } else if (_error == boost::asio::error::operation_aborted) {
            // endpoint was stopped
            shutdown_and_close_socket(false);
        } else {
            if (state_ == cei_state_e::CONNECTING) {
                VSOMEIP_WARNING << "tce::send_cbk endpoint is already restarting:"
                        << get_remote_information();
            } else {
                state_ = cei_state_e::CONNECTING;
                shutdown_and_close_socket(false);
                std::shared_ptr<endpoint_host> its_host = endpoint_host_.lock();
                if (its_host) {
                    its_host->on_disconnect(shared_from_this());
                }
                restart(true);
            }
            service_t its_service(0);
            method_t its_method(0);
            client_t its_client(0);
            session_t its_session(0);
            if (_sent_msg && _sent_msg->size() > VSOMEIP_SESSION_POS_MAX) {
                its_service = bithelper::read_uint16_be(&(*_sent_msg)[VSOMEIP_SERVICE_POS_MIN]);
                its_method  = bithelper::read_uint16_be(&(*_sent_msg)[VSOMEIP_METHOD_POS_MIN]);
                its_client  = bithelper::read_uint16_be(&(*_sent_msg)[VSOMEIP_CLIENT_POS_MIN]);
                its_session = bithelper::read_uint16_be(&(*_sent_msg)[VSOMEIP_SESSION_POS_MIN]);
            }
            VSOMEIP_WARNING << "tce::send_cbk received error: "
                    << _error.message() << " (" << std::dec
                    << _error.value() << ") " << get_remote_information()
                    << " " << std::dec << queue_.size()
                    << " " << std::dec << queue_size_ << " ("
                    << std::hex << std::setw(4) << std::setfill('0') << its_client <<"): ["
                    << std::hex << std::setw(4) << std::setfill('0') << its_service << "."
                    << std::hex << std::setw(4) << std::setfill('0') << its_method << "."
                    << std::hex << std::setw(4) << std::setfill('0') << its_session << "]";
        }
    }
}

std::uint32_t tcp_client_endpoint_impl::get_max_allowed_reconnects() const {
    return MAX_RECONNECTS_UNLIMITED;
}

void tcp_client_endpoint_impl::max_allowed_reconnects_reached() {
    return;
}

void tcp_client_endpoint_impl::wait_until_sent(const boost::system::error_code &_error) {
    if (_error && _error != boost::asio::error::operation_aborted) {
        // This Function is usually called with boost::asio::error::operation_aborted
        // and therefore its part of its normal execution path.
        VSOMEIP_WARNING << "tce::" << __func__ << "::  (" << _error.value()
                        << ") message: " << _error.message();
    }
    std::unique_lock<std::recursive_mutex> its_lock(mutex_);
    if (!is_sending_ || !_error) {
        its_lock.unlock();
        if (!_error)
            VSOMEIP_WARNING << __func__
                << ": Maximum wait time for send operation exceeded for tce.";

        std::shared_ptr<endpoint_host> its_ep_host = endpoint_host_.lock();
        its_ep_host->on_disconnect(shared_from_this());
        restart(true);
    } else {
        std::chrono::milliseconds its_timeout(VSOMEIP_MAX_TCP_SENT_WAIT_TIME);
        boost::system::error_code ec;
        sent_timer_.expires_from_now(its_timeout, ec);
        sent_timer_.async_wait(std::bind(&tcp_client_endpoint_impl::wait_until_sent,
                std::dynamic_pointer_cast<tcp_client_endpoint_impl>(shared_from_this()),
                std::placeholders::_1));
    }
}

} // namespace vsomeip_v3
