// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <deque>
#include <iomanip>
#include <sstream>

#include <sys/types.h>
#include <boost/asio/write.hpp>

#include <vsomeip/internal/logger.hpp>

#ifndef __QNX__
#include "../include/credentials.hpp"
#endif
#include "../include/endpoint_host.hpp"
#include "../include/local_uds_server_endpoint_impl.hpp"
#include "../include/local_server_endpoint_impl_receive_op.hpp"
#include "../../configuration/include/configuration.hpp"
#include "../../protocol/include/assign_client_command.hpp"
#include "../../protocol/include/assign_client_ack_command.hpp"
#include "../../routing/include/routing_host.hpp"
#include "../../security/include/policy_manager_impl.hpp"
#include "../../utility/include/bithelper.hpp"
#include "../../utility/include/utility.hpp"

namespace vsomeip_v3 {

local_uds_server_endpoint_impl::local_uds_server_endpoint_impl(
        const std::shared_ptr<endpoint_host>& _endpoint_host,
        const std::shared_ptr<routing_host>& _routing_host,
        boost::asio::io_context &_io,
        const std::shared_ptr<configuration>& _configuration,
        bool _is_routing_endpoint)
    : local_uds_server_endpoint_base_impl(_endpoint_host, _routing_host, _io, _configuration),
      acceptor_(_io),
      buffer_shrink_threshold_(_configuration->get_buffer_shrink_threshold()),
      is_routing_endpoint_(_is_routing_endpoint) {
    is_supporting_magic_cookies_ = false;

    this->max_message_size_ = _configuration->get_max_message_size_local();
    this->queue_limit_ = _configuration->get_endpoint_queue_limit_local();
}

void local_uds_server_endpoint_impl::init(const endpoint_type& _local,
                                          boost::system::error_code& _error) {
    std::lock_guard<std::mutex> its_lock(acceptor_mutex_);
    acceptor_.open(_local.protocol(), _error);
    if (_error)
        return;

    init_helper(_local, _error);
}

void local_uds_server_endpoint_impl::init(const endpoint_type& _local, const int _socket,
                                          boost::system::error_code& _error) {
    std::lock_guard<std::mutex> its_lock(acceptor_mutex_);
    acceptor_.assign(_local.protocol(), _socket, _error);
    if (_error)
        return;

    init_helper(_local, _error);
}

void local_uds_server_endpoint_impl::init_helper(const endpoint_type& _local,
                                                 boost::system::error_code& _error) {
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), _error);
    if (_error)
        return;

    acceptor_.bind(_local, _error);
    if (_error)
        return;

    acceptor_.listen(boost::asio::socket_base::max_connections, _error);
    if (_error)
        return;

#ifndef __QNX__
    if (chmod(_local.path().c_str(),
            static_cast<mode_t>(configuration_->get_permissions_uds())) == -1) {
        VSOMEIP_ERROR << __func__ << ": chmod: " << strerror(errno);
    }
    credentials::activate_credentials(acceptor_.native_handle());
#endif

    local_ = _local;

}

void local_uds_server_endpoint_impl::deinit() {
    std::lock_guard<std::mutex> its_lock(acceptor_mutex_);
    boost::system::error_code its_error;
    acceptor_.close(its_error);
}

void local_uds_server_endpoint_impl::start() {
    std::lock_guard<std::mutex> its_lock(acceptor_mutex_);
    if (acceptor_.is_open()) {
        connection::ptr new_connection = connection::create(
                std::dynamic_pointer_cast<local_uds_server_endpoint_impl>(
                        shared_from_this()), max_message_size_,
                        buffer_shrink_threshold_,
                        io_);

        {
            std::unique_lock<std::mutex> its_lock(new_connection->get_socket_lock());
            acceptor_.async_accept(
                new_connection->get_socket(),
                std::bind(
                    &local_uds_server_endpoint_impl::accept_cbk,
                    std::dynamic_pointer_cast<
                        local_uds_server_endpoint_impl
                    >(shared_from_this()),
                    new_connection,
                    std::placeholders::_1
                )
            );
        }
    }
}

void local_uds_server_endpoint_impl::stop() {

    server_endpoint_impl::stop();
    {
        std::lock_guard<std::mutex> its_lock(acceptor_mutex_);
        if (acceptor_.is_open()) {
            boost::system::error_code its_error;
            acceptor_.close(its_error);
        }
    }
    {
        std::lock_guard<std::mutex> its_lock(connections_mutex_);
        for (const auto &c : connections_) {
            c.second->stop();
        }
        connections_.clear();
    }
}

bool local_uds_server_endpoint_impl::is_local() const {
    return true;
}

bool local_uds_server_endpoint_impl::send(const uint8_t *_data, uint32_t _size) {
#if 0
    std::stringstream msg;
    msg << "lse::send ";
    for (uint32_t i = 0; i < _size; i++)
        msg << std::setw(2) << std::setfill('0') << std::hex << (int)_data[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    std::lock_guard<std::mutex> its_lock(mutex_);
    if (endpoint_impl::sending_blocked_) {
        return false;
    }

    client_t its_client;
    std::memcpy(&its_client, &_data[protocol::COMMAND_HEADER_SIZE], sizeof(its_client));

    connection::ptr its_connection;
    {
        std::lock_guard<std::mutex> its_lock(connections_mutex_);
        const auto its_iterator = connections_.find(its_client);
        if (its_iterator == connections_.end()) {
            return false;
        } else {
            its_connection = its_iterator->second;
        }
    }

    auto its_buffer = std::make_shared<message_buffer_t>();
    its_buffer->insert(its_buffer->end(), _data, _data + _size);
    its_connection->send_queued(its_buffer);

    return true;
}

bool local_uds_server_endpoint_impl::send_to(
        const std::shared_ptr<endpoint_definition> _target,
        const byte_t *_data, uint32_t _size) {

    (void)_target;
    (void)_data;
    (void)_size;
    return false;
}

bool local_uds_server_endpoint_impl::send_error(
        const std::shared_ptr<endpoint_definition> _target,
        const byte_t *_data, uint32_t _size) {

    (void)_target;
    (void)_data;
    (void)_size;
    return false;
}

bool local_uds_server_endpoint_impl::send_queued(
        const target_data_iterator_type _it) {

    (void)_it;

    return false;
}

void local_uds_server_endpoint_impl::receive() {
    // intentionally left empty
}

bool local_uds_server_endpoint_impl::get_default_target(
        service_t,
        local_uds_server_endpoint_impl::endpoint_type &) const {

    return false;
}

bool local_uds_server_endpoint_impl::add_connection(const client_t &_client,
        const std::shared_ptr<connection> &_connection) {

    bool ret = false;
    std::lock_guard<std::mutex> its_lock(connections_mutex_);
    auto find_connection = connections_.find(_client);
    if (find_connection == connections_.end()) {
        connections_[_client] = _connection;
        ret = true;
    } else {
        VSOMEIP_WARNING << "Attempt to add already existing "
            "connection to client " << std::hex << _client;
    }
    return ret;
}

void local_uds_server_endpoint_impl::remove_connection(
        const client_t &_client) {

    std::lock_guard<std::mutex> its_lock(connections_mutex_);
    connections_.erase(_client);
}

void local_uds_server_endpoint_impl::accept_cbk(
        const connection::ptr& _connection, boost::system::error_code const &_error) {
    if (_error != boost::asio::error::bad_descriptor
            && _error != boost::asio::error::operation_aborted
            && _error != boost::asio::error::no_descriptors) {
        start();
    } else if (_error == boost::asio::error::no_descriptors) {
        VSOMEIP_ERROR << "local_usd_server_endpoint_impl::accept_cbk: "
                << _error.message() << " (" << std::dec << _error.value()
                << ") Will try to accept again in 1000ms";
        auto its_timer =
                std::make_shared<boost::asio::steady_timer>(io_,
                        std::chrono::milliseconds(1000));
        auto its_ep = std::dynamic_pointer_cast<local_uds_server_endpoint_impl>(
                shared_from_this());
        its_timer->async_wait([its_timer, its_ep]
                               (const boost::system::error_code& _error) {
            if (!_error) {
                its_ep->start();
            }
        });
    }

    if (!_error) {
#ifndef __QNX__
        auto its_host = endpoint_host_.lock();
        client_t its_client = 0;
        std::string its_client_host;
        vsomeip_sec_client_t its_sec_client;

        its_sec_client.port = VSOMEIP_SEC_PORT_UNUSED;
        its_sec_client.user = ANY_UID;
        its_sec_client.group = ANY_GID;

        socket_type &its_socket = _connection->get_socket();
        if (auto creds = credentials::receive_credentials(its_socket.native_handle())) {

            its_client = std::get<0>(*creds);
            its_client_host = std::get<3>(*creds);

            its_sec_client.user = std::get<1>(*creds);
            its_sec_client.group = std::get<2>(*creds);
        } else {
            VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_host->get_client()
                    << " is rejecting new connection because client credentials couldn't be received!";
            boost::system::error_code er;
            its_socket.shutdown(its_socket.shutdown_both, er);
            its_socket.close(er);
            return;
        }

        if (its_host && configuration_->is_security_enabled()) {
            if (!configuration_->check_routing_credentials(its_client, &its_sec_client)) {
                VSOMEIP_WARNING << "vSomeIP Security: Rejecting new connection with routing manager client ID 0x"
                        << std::hex << its_client
                        << " uid/gid= " << std::dec
                        << its_sec_client.user << "/"
                        << its_sec_client.group
                        << " because passed credentials do not match with routing manager credentials!";
                boost::system::error_code er;
                its_socket.shutdown(its_socket.shutdown_both, er);
                its_socket.close(er);
                return;
            }

            if (is_routing_endpoint_) {
                // rm_impl receives VSOMEIP_CLIENT_UNSET initially -> check later
                _connection->set_bound_sec_client(its_sec_client);
                _connection->set_bound_client_host(its_client_host);
            } else {
                {
                    std::lock_guard<std::mutex> its_connection_lock(connections_mutex_);
                    // rm_impl receives VSOMEIP_CLIENT_UNSET initially -> check later
                    const auto found_client = connections_.find(its_client);
                    if (found_client != connections_.end()) {
                        VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex
                                << its_host->get_client() << " is rejecting new connection with client ID 0x"
                                << its_client << " uid/gid= " << std::dec
                                << its_sec_client.user << "/"
                                << its_sec_client.group
                                << " because of already existing connection using same client ID";
                        boost::system::error_code er;
                        its_socket.shutdown(its_socket.shutdown_both, er);
                        its_socket.close(er);
                        return;
                    }
                }

                // Add to known clients (loads new config if needed)
                std::shared_ptr<routing_host> its_routing_host = routing_host_.lock();
                its_routing_host->add_known_client(its_client, its_client_host);

               if (!configuration_->get_policy_manager()->check_credentials(its_client, &its_sec_client)) {
                     VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex
                             << its_host->get_client() << " received client credentials from client 0x"
                             << its_client << " which violates the security policy : uid/gid="
                             << std::dec << its_sec_client.user << "/"
                             << its_sec_client.group;
                     boost::system::error_code er;
                     its_socket.shutdown(its_socket.shutdown_both, er);
                     its_socket.close(er);
                     return;
                }
                // rm_impl receives VSOMEIP_CLIENT_UNSET initially -> set later
                _connection->set_bound_client(its_client);
                _connection->set_bound_client_host(its_client_host);
                add_connection(its_client, _connection);
            }
        } else {
            configuration_->get_policy_manager()->store_client_to_sec_client_mapping(its_client, &its_sec_client);
            configuration_->get_policy_manager()->store_sec_client_to_client_mapping(&its_sec_client, its_client);

            if (!is_routing_endpoint_) {
                std::shared_ptr<routing_host> its_routing_host = routing_host_.lock();
                its_routing_host->add_known_client(its_client, its_client_host);
                _connection->set_bound_client(its_client);
            }
            _connection->set_bound_client_host(its_client_host);
        }
#endif
        _connection->start();
    }
}

///////////////////////////////////////////////////////////////////////////////
// class local_service_impl::connection
///////////////////////////////////////////////////////////////////////////////

local_uds_server_endpoint_impl::connection::connection(
        const std::shared_ptr<local_uds_server_endpoint_impl>& _server,
        std::uint32_t _max_message_size,
        std::uint32_t _initial_recv_buffer_size,
        std::uint32_t _buffer_shrink_threshold,
        boost::asio::io_context &_io)
    : socket_(_io),
      server_(_server),
      recv_buffer_size_initial_(_initial_recv_buffer_size + 8),
      max_message_size_(_max_message_size),
      recv_buffer_(recv_buffer_size_initial_, 0),
      recv_buffer_size_(0),
      missing_capacity_(0),
      shrink_count_(0),
      buffer_shrink_threshold_(_buffer_shrink_threshold),
      bound_client_(VSOMEIP_CLIENT_UNSET),
      bound_client_host_(""),
      assigned_client_(false),
      is_stopped_(true) {
    if (_server->is_routing_endpoint_ &&
            !_server->configuration_->is_security_enabled()) {
        assigned_client_ = true;
    }

    sec_client_.user = ANY_UID;
    sec_client_.group = ANY_GID;
}

local_uds_server_endpoint_impl::connection::ptr
local_uds_server_endpoint_impl::connection::create(
        const std::shared_ptr<local_uds_server_endpoint_impl>& _server,
        std::uint32_t _max_message_size,
        std::uint32_t _buffer_shrink_threshold,
        boost::asio::io_context &_io) {
    const std::uint32_t its_initial_buffer_size
                = static_cast<std::uint32_t>(protocol::COMMAND_HEADER_SIZE
                        + sizeof(instance_t) + sizeof(bool) + sizeof(bool));
    return ptr(new connection(_server, _max_message_size, its_initial_buffer_size,
            _buffer_shrink_threshold, _io));
}

local_uds_server_endpoint_impl::socket_type &
local_uds_server_endpoint_impl::connection::get_socket() {
    return socket_;
}

std::unique_lock<std::mutex>
local_uds_server_endpoint_impl::connection::get_socket_lock() {
    return std::unique_lock<std::mutex>(socket_mutex_);
}

void local_uds_server_endpoint_impl::connection::start() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    if (socket_.is_open()) {
        const std::size_t its_capacity(recv_buffer_.capacity());
        if (recv_buffer_size_ > its_capacity) {
            VSOMEIP_ERROR << __func__ << "Received buffer size is greater than the buffer capacity!"
                << " recv_buffer_size_: " << recv_buffer_size_
                << " its_capacity: " << its_capacity;
            return;
        }
        size_t left_buffer_size = its_capacity - recv_buffer_size_;
        try {
            if (missing_capacity_) {
                if (missing_capacity_ > MESSAGE_SIZE_UNLIMITED) {
                    VSOMEIP_ERROR << "Missing receive buffer capacity exceeds allowed maximum!";
                    return;
                }
                const std::size_t its_required_capacity(recv_buffer_size_ + missing_capacity_);
                if (its_capacity < its_required_capacity) {
                    // Make the resize to its_required_capacity
                    recv_buffer_.reserve(its_required_capacity);
                    recv_buffer_.resize(its_required_capacity, 0x0);
                }
                left_buffer_size = missing_capacity_;
                missing_capacity_ = 0;
            } else if (buffer_shrink_threshold_
                    && shrink_count_ > buffer_shrink_threshold_
                    && recv_buffer_size_ == 0) {
                // In this case, make the resize to recv_buffer_size_initial_
                recv_buffer_.resize(recv_buffer_size_initial_, 0x0);
                recv_buffer_.shrink_to_fit();
                // And set buffer_size to recv_buffer_size_initial_, the same of our resize
                left_buffer_size = recv_buffer_size_initial_;
                shrink_count_ = 0;
            }
        } catch (const std::exception &e) {
            handle_recv_buffer_exception(e);
            // don't start receiving again
            return;
        }

        is_stopped_ = false;
        auto its_storage = std::make_shared<local_endpoint_receive_op::storage>(
            socket_,
            std::bind(
                &local_uds_server_endpoint_impl::connection::receive_cbk,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2,
                std::placeholders::_3,
                std::placeholders::_4
            ),
            &recv_buffer_[recv_buffer_size_],
            left_buffer_size,
            std::numeric_limits<std::uint32_t>::max(),
            std::numeric_limits<std::uint32_t>::max(),
            std::numeric_limits<std::size_t>::min()
        );

        socket_.async_wait(socket_type::wait_read, local_endpoint_receive_op::receive_cb(its_storage));
    }
}

void local_uds_server_endpoint_impl::connection::stop() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    is_stopped_ = true;
    if (socket_.is_open()) {
        if (-1 == fcntl(socket_.native_handle(), F_GETFD)) {
            VSOMEIP_ERROR << "lse: socket/handle closed already '" << std::string(std::strerror(errno))
                          << "' (" << errno << ") " << get_path_local();
        }
        boost::system::error_code its_error;
        socket_.cancel(its_error);
    }
}

void local_uds_server_endpoint_impl::connection::send_queued(
        const message_buffer_ptr_t& _buffer) {

    std::shared_ptr<local_uds_server_endpoint_impl> its_server(server_.lock());
    if (!its_server) {
        VSOMEIP_TRACE << "local_uds_server_endpoint_impl::connection::send_queued "
                " couldn't lock server_";
        return;
    }

    static const byte_t its_start_tag[] = { 0x67, 0x37, 0x6D, 0x07 };
    static const byte_t its_end_tag[] = { 0x07, 0x6D, 0x37, 0x67 };
    std::vector<boost::asio::const_buffer> bufs;

#if 0
        std::stringstream msg;
        msg << "lse::sq: ";
        for (std::size_t i = 0; i < _buffer->size(); i++)
            msg << std::setw(2) << std::setfill('0') << std::hex
                << (int)(*_buffer)[i] << " ";
        VSOMEIP_INFO << msg.str();
#endif

    bufs.push_back(boost::asio::buffer(its_start_tag));
    bufs.push_back(boost::asio::buffer(*_buffer));
    bufs.push_back(boost::asio::buffer(its_end_tag));

    {
        std::lock_guard<std::mutex> its_lock(socket_mutex_);
        boost::asio::async_write(
            socket_,
            bufs,
            std::bind(
                &local_uds_server_endpoint_impl::connection::send_cbk,
                shared_from_this(),
                _buffer,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
}

client_t local_uds_server_endpoint_impl::assign_client(
        const byte_t *_data, uint32_t _size) {

    std::vector<byte_t> its_data(_data, _data + _size);

    protocol::assign_client_command its_command;
    protocol::error_e its_error;

    its_command.deserialize(its_data, its_error);
    if (its_error != protocol::error_e::ERROR_OK) {
        VSOMEIP_ERROR << __func__
                << ": assign client command deserialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
        return VSOMEIP_CLIENT_UNSET;
    }

    return utility::request_client_id(configuration_,
            its_command.get_name(), its_command.get_client());
}

void local_uds_server_endpoint_impl::get_configured_times_from_endpoint(
        service_t _service,
        method_t _method, std::chrono::nanoseconds *_debouncing,
        std::chrono::nanoseconds *_maximum_retention) const {
    (void)_service;
    (void)_method;
    (void)_debouncing;
    (void)_maximum_retention;
    VSOMEIP_ERROR << "local_uds_server_endpoint_impl::get_configured_times_from_endpoint.";
}

void local_uds_server_endpoint_impl::connection::send_cbk(const message_buffer_ptr_t _buffer,
        boost::system::error_code const &_error, std::size_t _bytes) {
    (void)_buffer;
    (void)_bytes;
    if (_error)
        VSOMEIP_WARNING << "sei::send_cbk received error: " << _error.message();
}

void local_uds_server_endpoint_impl::connection::receive_cbk(
        boost::system::error_code const &_error, std::size_t _bytes,
        std::uint32_t const &_uid, std::uint32_t const &_gid)
{
    std::shared_ptr<local_uds_server_endpoint_impl> its_server(server_.lock());
    if (!its_server) {
        VSOMEIP_TRACE << "local_uds_server_endpoint_impl::connection::receive_cbk "
                " couldn't lock server_";
        return;
    }
    std::shared_ptr<routing_host> its_host = its_server->routing_host_.lock();
    if (!its_host)
        return;

    std::shared_ptr<vsomeip_v3::configuration> its_config = its_server->configuration_;
    if (_error == boost::asio::error::operation_aborted) {
        if (its_server->is_routing_endpoint_ &&
                bound_client_ != VSOMEIP_CLIENT_UNSET && its_config) {
            utility::release_client_id(its_config->get_network(),
                    bound_client_);
            set_bound_client(VSOMEIP_CLIENT_UNSET);
        }

        // connection was stopped
        return;
    }

    bool is_error(false);
    std::size_t its_start = 0;
    std::size_t its_end = 0;
    std::size_t its_iteration_gap = 0;
    std::uint32_t its_command_size = 0;

    if (!_error && 0 < _bytes) {
#if 0
        std::stringstream msg;
        msg << "lse::c<" << this << ">rcb: ";
        for (std::size_t i = 0; i < _bytes + recv_buffer_size_; i++)
            msg << std::setw(2) << std::setfill('0') << std::hex
                << (int) (recv_buffer_[i]) << " ";
        VSOMEIP_INFO << msg.str();
#endif

        if (recv_buffer_size_ + _bytes < recv_buffer_size_) {
            VSOMEIP_ERROR << "receive buffer overflow in local server endpoint ~> abort!";
            return;
        }
        recv_buffer_size_ += _bytes;

        bool message_is_empty(false);
        bool found_message(false);

        do {
            found_message = false;
            message_is_empty = false;

            its_start = 0 + its_iteration_gap;
            if (its_start + 3 < its_start) {
                VSOMEIP_ERROR << "buffer overflow in local server endpoint ~> abort!";
                return;
            }
            while (its_start + 3 < recv_buffer_size_ + its_iteration_gap &&
                (recv_buffer_[its_start] != 0x67 ||
                recv_buffer_[its_start+1] != 0x37 ||
                recv_buffer_[its_start+2] != 0x6d ||
                recv_buffer_[its_start+3] != 0x07)) {
                its_start++;
            }

            if (its_start + 3 == recv_buffer_size_ + its_iteration_gap) {
                message_is_empty = true;
            } else {
                its_start += 4;
            }

            if (!message_is_empty) {
                if (its_start + protocol::COMMAND_POSITION_SIZE + 3 < recv_buffer_size_ + its_iteration_gap) {
                    its_command_size = bithelper::read_uint32_le(&recv_buffer_[its_start + protocol::COMMAND_POSITION_SIZE]);
                    its_end = its_start + protocol::COMMAND_POSITION_SIZE + 3 + its_command_size;
                } else {
                    its_end = its_start;
                }
                if (its_command_size && max_message_size_ != MESSAGE_SIZE_UNLIMITED
                        && its_command_size > max_message_size_) {
                    std::lock_guard<std::mutex> its_lock(socket_mutex_);
                    VSOMEIP_ERROR << "Received a local message which exceeds "
                          << "maximum message size (" << std::dec << its_command_size
                          << ") aborting! local: " << get_path_local() << " remote: "
                          << get_path_remote();
                    recv_buffer_.resize(recv_buffer_size_initial_, 0x0);
                    recv_buffer_.shrink_to_fit();
                    return;
                }
                if (its_end + 3 < its_end) {
                    VSOMEIP_ERROR << "buffer overflow in local server endpoint ~> abort!";
                    return;
                }
                while (its_end + 3 < recv_buffer_size_ + its_iteration_gap &&
                    (recv_buffer_[its_end] != 0x07 ||
                    recv_buffer_[its_end+1] != 0x6d ||
                    recv_buffer_[its_end+2] != 0x37 ||
                    recv_buffer_[its_end+3] != 0x67)) {
                    its_end ++;
                }
                if (its_end + 4 < its_end) {
                    VSOMEIP_ERROR << "buffer overflow in local server endpoint ~> abort!";
                    return;
                }
                // check if we received a full message
                if (recv_buffer_size_ + its_iteration_gap < its_end + 4
                        || recv_buffer_[its_end] != 0x07
                        || recv_buffer_[its_end+1] != 0x6d
                        || recv_buffer_[its_end+2] != 0x37
                        || recv_buffer_[its_end+3] != 0x67) {
                    // command (1 Byte) + version (2 Byte) + client id (2 Byte)
                    // + command size (4 Byte) + data itself + stop tag (4 byte)
                    // = 13 Bytes not covered in command size.
                    // If need to change the recv_buffer_, change the value of missing_capacity_
                    // in this if/else, otherwise it is 0
                    if (its_start - its_iteration_gap + its_command_size
                            + protocol::COMMAND_HEADER_SIZE + protocol::TAG_SIZE  > recv_buffer_size_) {
                        missing_capacity_ =
                                std::uint32_t(its_start) - std::uint32_t(its_iteration_gap)
                                + its_command_size + std::uint32_t(protocol::COMMAND_HEADER_SIZE + protocol::TAG_SIZE)
                                - std::uint32_t(recv_buffer_size_);
                    } else if (recv_buffer_size_ < protocol::COMMAND_HEADER_SIZE + protocol::TAG_SIZE) {
                        // to little data to read out the command size
                        // minimal amount of data needed to read out command size = header + tag size
                        missing_capacity_ = static_cast<std::uint32_t>(
                                protocol::COMMAND_HEADER_SIZE + protocol::TAG_SIZE - recv_buffer_size_);
                    } else {
                        std::stringstream local_msg;
                        local_msg << std::setfill('0') << std::hex;
                        for (std::size_t i = its_iteration_gap;
                                i < recv_buffer_size_ + its_iteration_gap &&
                                i - its_iteration_gap < 32; i++) {
                            local_msg << std::setw(2) << (int) recv_buffer_[i] << " ";
                        }
                        VSOMEIP_ERROR << "lse::c<" << this
                                << ">rcb: recv_buffer_size is: " << std::dec
                                << recv_buffer_size_ << " but couldn't read "
                                "out command size. recv_buffer_capacity: "
                                << std::dec << recv_buffer_.capacity()
                                << " its_iteration_gap: " << std::dec
                                << its_iteration_gap << " bound client: 0x"
                                << std::hex << bound_client_ << " buffer: "
                                << local_msg.str();
                        recv_buffer_size_ = 0;
                        missing_capacity_ = 0;
                        its_iteration_gap = 0;
                        message_is_empty = true;
                    }
                }
            }

            if (!message_is_empty &&
                its_end + 3 < recv_buffer_size_ + its_iteration_gap) {

                if (its_server->is_routing_endpoint_
                        && recv_buffer_[its_start] == byte_t(protocol::id_e::ASSIGN_CLIENT_ID)) {
                    client_t its_client = its_server->assign_client(
                            &recv_buffer_[its_start], uint32_t(its_end - its_start));

                    if (its_config && its_config->is_security_enabled()) {
                        // Add to known clients (loads new config if needed)
                        its_host->add_known_client(its_client, get_bound_client_host());

                        if (!its_server->add_connection(its_client, shared_from_this())) {
                            VSOMEIP_WARNING << std::hex << "Client 0x" << its_host->get_client()
                                    << " is rejecting new connection with client ID 0x" << its_client
                                    << " uid/gid= " << std::dec
                                    << sec_client_.user << "/"
                                    << sec_client_.group
                                    << " because of already existing connection using same client ID";
                            stop();
                            return;
                        } else if (!its_server->configuration_->get_policy_manager()->check_credentials(
                                its_client, &sec_client_)) {
                            VSOMEIP_WARNING << std::hex << "Client 0x" << its_host->get_client()
                                    << " received client credentials from client 0x" << its_client
                                    << " which violates the security policy : uid/gid="
                                    << std::dec << sec_client_.user << "/"
                                    << sec_client_.group;
                            its_server->remove_connection(its_client);
                            utility::release_client_id(its_config->get_network(),
                                    its_client);
                            stop();
                            return;
                        }
                        else {
                            set_bound_client(its_client);
                        }
                    } else {
                        set_bound_client(its_client);
                        its_host->add_known_client(its_client, get_bound_client_host());
                        its_server->add_connection(its_client, shared_from_this());
                    }
                    its_server->send_client_identifier(its_client);
                    assigned_client_ = true;
                } else if (!its_server->is_routing_endpoint_ || assigned_client_) {

                    vsomeip_sec_client_t its_sec_client{};

                    its_sec_client.port = VSOMEIP_SEC_PORT_UNUSED;
                    its_sec_client.user = _uid;
                    its_sec_client.group = _gid;

                    its_host->on_message(&recv_buffer_[its_start],
                                         uint32_t(its_end - its_start), its_server.get(),
                                         false, bound_client_, &its_sec_client);
                } else {
                    VSOMEIP_WARNING << std::hex << "Client 0x" << its_host->get_client()
                            << " didn't receive VSOMEIP_ASSIGN_CLIENT as first message";
                }
                #if 0
                        std::stringstream local_msg;
                        local_msg << "lse::c<" << this << ">rcb::thunk: ";
                        for (std::size_t i = its_start; i < its_end; i++)
                            local_msg << std::setw(2) << std::setfill('0') << std::hex
                                << (int) recv_buffer_[i] << " ";
                        VSOMEIP_INFO << local_msg.str();
                #endif
                calculate_shrink_count();
                recv_buffer_size_ -= (its_end + 4 - its_iteration_gap);
                missing_capacity_ = 0;
                its_command_size = 0;
                found_message = true;
                its_iteration_gap = its_end + 4;
            } else {
                if (its_iteration_gap) {
                    // Message not complete and not in front of the buffer!
                    // Copy last part to front for consume in future receive_cbk call!
                    for (size_t i = 0; i < recv_buffer_size_; ++i) {
                        recv_buffer_[i] = recv_buffer_[i + its_iteration_gap];
                    }
                    // Still more capacity needed after shifting everything to front?
                    if (missing_capacity_ &&
                            missing_capacity_ <= recv_buffer_.capacity() - recv_buffer_size_) {
                        missing_capacity_ = 0;
                    }
                } else if (message_is_empty) {
                    VSOMEIP_ERROR << "Received garbage data.";
                    is_error = true;
                }
            }
        } while (recv_buffer_size_ > 0 && found_message);
    }

    if (is_stopped_
            || _error == boost::asio::error::eof
            || _error == boost::asio::error::connection_reset
            || is_error) {
        shutdown_and_close();
        its_server->remove_connection(bound_client_);
        its_server->configuration_->get_policy_manager()->remove_client_to_sec_client_mapping(bound_client_);
    } else if (_error != boost::asio::error::bad_descriptor) {
        start();
    }
}

void local_uds_server_endpoint_impl::connection::set_bound_client(client_t _client) {
    bound_client_ = _client;
}

client_t local_uds_server_endpoint_impl::connection::get_bound_client() const {
    return bound_client_;
}

void local_uds_server_endpoint_impl::connection::set_bound_client_host(
        const std::string &_bound_client_host) {

    bound_client_host_ = _bound_client_host;
}

std::string local_uds_server_endpoint_impl::connection::get_bound_client_host() const {
    return bound_client_host_;
}


void local_uds_server_endpoint_impl::connection::set_bound_sec_client(
        const vsomeip_sec_client_t &_sec_client) {

    sec_client_ = _sec_client;
}

void local_uds_server_endpoint_impl::connection::calculate_shrink_count() {
    if (buffer_shrink_threshold_) {
        if (recv_buffer_.capacity() != recv_buffer_size_initial_) {
            if (recv_buffer_size_ < (recv_buffer_.capacity() >> 1)) {
                shrink_count_++;
            } else {
                shrink_count_ = 0;
            }
        }
    }
}

std::string local_uds_server_endpoint_impl::connection::get_path_local() const {
    boost::system::error_code ec;
    std::string its_local_path;
    if (socket_.is_open()) {
        endpoint_type its_local_endpoint = socket_.local_endpoint(ec);
        if (!ec) {
            its_local_path += its_local_endpoint.path();
        }
    }
    return its_local_path;
}

std::string local_uds_server_endpoint_impl::connection::get_path_remote() const {
    boost::system::error_code ec;
    std::string its_remote_path;
    if (socket_.is_open()) {
        endpoint_type its_remote_endpoint = socket_.remote_endpoint(ec);
        if (!ec) {
            its_remote_path += its_remote_endpoint.path();
        }
    }
    return its_remote_path;
}

void local_uds_server_endpoint_impl::connection::handle_recv_buffer_exception(
        const std::exception &_e) {
    std::stringstream its_message;
    its_message << "local_uds_server_endpoint_impl::connection catched exception"
            << _e.what() << " local: " << get_path_local() << " remote: "
            << get_path_remote() << " shutting down connection. Start of buffer: "
            << std::setfill('0') << std::hex;

    for (std::size_t i = 0; i < recv_buffer_size_ && i < 16; i++) {
        its_message << std::setw(2) << (int) (recv_buffer_[i]) << " ";
    }

    its_message << " Last 16 Bytes captured: ";
    for (int i = 15; recv_buffer_size_ > 15u && i >= 0; i--) {
        its_message << std::setw(2) << (int) (recv_buffer_[static_cast<size_t>(i)]) << " ";
    }
    VSOMEIP_ERROR << its_message.str();
    recv_buffer_.clear();
    if (socket_.is_open()) {
        if (-1 == fcntl(socket_.native_handle(), F_GETFD)) {
            VSOMEIP_ERROR << "lse: socket/handle closed already '" << std::string(std::strerror(errno))
                          << "' (" << errno << ") " << get_path_local();
        }

    }
    std::shared_ptr<local_uds_server_endpoint_impl> its_server = server_.lock();
    if (its_server) {
        its_server->remove_connection(bound_client_);
    }
}

std::size_t
local_uds_server_endpoint_impl::connection::get_recv_buffer_capacity() const {
    return recv_buffer_.capacity();
}

void
local_uds_server_endpoint_impl::connection::shutdown_and_close() {
    std::lock_guard<std::mutex> its_lock(socket_mutex_);
    shutdown_and_close_unlocked();
}

void
local_uds_server_endpoint_impl::connection::shutdown_and_close_unlocked() {
    boost::system::error_code its_error;
    socket_.shutdown(socket_.shutdown_both, its_error);
    socket_.close(its_error);
}

void local_uds_server_endpoint_impl::print_status() {
    std::lock_guard<std::mutex> its_lock(mutex_);
    connections_t its_connections;
    {
        std::lock_guard<std::mutex> its_lock(connections_mutex_);
        its_connections = connections_;
    }

    std::string its_local_path(local_.path());

    VSOMEIP_INFO << "status lse: " << its_local_path << " connections: "
            << std::dec << its_connections.size() << " targets: "
            << std::dec << targets_.size();
    for (const auto &c : its_connections) {
        std::string its_remote_path; // TODO: construct the path

        std::size_t its_recv_size(0);
        {
            std::unique_lock<std::mutex> c_s_lock(c.second->get_socket_lock());
            its_recv_size = c.second->get_recv_buffer_capacity();
        }

        VSOMEIP_INFO << "status lse: client: " << its_remote_path
                << " recv_buffer: " << std::dec << its_recv_size;
    }
}

std::string local_uds_server_endpoint_impl::get_remote_information(
        const target_data_iterator_type _it) const {

    (void)_it;
    return "local";
}

std::string local_uds_server_endpoint_impl::get_remote_information(
        const endpoint_type& _remote) const {

    (void)_remote;
    return "local";
}

bool local_uds_server_endpoint_impl::is_reliable() const {
    return false;
}

std::uint16_t local_uds_server_endpoint_impl::get_local_port() const {

    return 0;
}

void local_uds_server_endpoint_impl::set_local_port(std::uint16_t _port) {

    (void)_port;
    // Intentionally left empty
}

bool local_uds_server_endpoint_impl::check_packetizer_space(
        target_data_iterator_type _it, message_buffer_ptr_t* _packetizer,
        std::uint32_t _size) {

    if ((*_packetizer)->size() + _size < (*_packetizer)->size()) {
        VSOMEIP_ERROR << "Overflow in packetizer addition ~> abort sending!";
        return false;
    }
    if ((*_packetizer)->size() + _size > max_message_size_
            && !(*_packetizer)->empty()) {
        _it->second.queue_.push_back(std::make_pair(*_packetizer, 0));
        _it->second.queue_size_ += (*_packetizer)->size();
        *_packetizer = std::make_shared<message_buffer_t>();
    }
    return true;
}

void
local_uds_server_endpoint_impl::send_client_identifier(
        const client_t &_client) {

    protocol::assign_client_ack_command its_command;
    its_command.set_client(VSOMEIP_ROUTING_CLIENT);
    its_command.set_assigned(_client);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);
    if (its_error != protocol::error_e::ERROR_OK) {

        VSOMEIP_ERROR << __func__
                << ": assign client ack command serialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
        return;
    }

    send(&its_buffer[0], static_cast<uint32_t>(its_buffer.size()));
}

} // namespace vsomeip_v3
