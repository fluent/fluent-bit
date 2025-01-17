// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <sstream>
#include <thread>

#include <boost/asio/ip/multicast.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/endpoint_definition.hpp"
#include "../include/endpoint_host.hpp"
#include "../include/tp.hpp"
#include "../include/udp_server_endpoint_impl.hpp"
#include "../include/udp_server_endpoint_impl_receive_op.hpp"
#include "../../configuration/include/configuration.hpp"
#include "../../routing/include/routing_host.hpp"
#include "../../service_discovery/include/defines.hpp"
#include "../../utility/include/bithelper.hpp"
#include "../../utility/include/utility.hpp"

namespace ip = boost::asio::ip;

namespace vsomeip_v3 {

udp_server_endpoint_impl::udp_server_endpoint_impl(
        const std::shared_ptr<endpoint_host>& _endpoint_host,
        const std::shared_ptr<routing_host>& _routing_host,
        boost::asio::io_context& _io, const std::shared_ptr<configuration>& _configuration) :
    server_endpoint_impl<ip::udp>(_endpoint_host, _routing_host, _io, _configuration),
    unicast_recv_buffer_(VSOMEIP_MAX_UDP_MESSAGE_SIZE, 0),
    is_v4_(false), multicast_id_(0), joined_group_(false), netmask_(_configuration->get_netmask()),
    prefix_(_configuration->get_prefix()),
    tp_reassembler_(std::make_shared<tp::tp_reassembler>(
            _configuration->get_max_message_size_unreliable(), _io)),
    tp_cleanup_timer_(_io), is_stopped_(true), on_unicast_sent_ {nullptr},
    receive_own_multicast_messages_(false), on_sent_multicast_received_ {nullptr} {
    is_supporting_someip_tp_ = true;
}

bool udp_server_endpoint_impl::is_local() const {
    return false;
}

void udp_server_endpoint_impl::init(const endpoint_type& _local,
                                    boost::system::error_code& _error) {

    if (!unicast_socket_) {
        unicast_socket_ = std::make_shared<socket_type>(io_, _local.protocol());
        if (!unicast_socket_) {
            _error = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return;
        }
    }

    if (!unicast_socket_->is_open()) {
        unicast_socket_->open(_local.protocol(), _error);
        if (_error)
            return;
    }

    boost::asio::socket_base::reuse_address optionReuseAddress(true);
    unicast_socket_->set_option(optionReuseAddress, _error);
    if (_error)
        return;

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    // If specified, bind to device
    std::string its_device(configuration_->get_device());
    if (its_device != "") {
        if (setsockopt(unicast_socket_->native_handle(), SOL_SOCKET, SO_BINDTODEVICE,
                its_device.c_str(), static_cast<socklen_t>(its_device.size())) == -1) {
            VSOMEIP_WARNING << "UDP Server: Could not bind to device \"" << its_device << "\"";
        }
    }
#endif

    unicast_socket_->bind(_local, _error);
    if (_error)
        return;

    if (_local.address().is_v4()) {
        is_v4_ = true;
        boost::asio::ip::multicast::outbound_interface option(_local.address().to_v4());
        unicast_socket_->set_option(option, _error);
        if (_error)
            return;
    } else {
        boost::asio::ip::multicast::outbound_interface option(
                static_cast<unsigned int>(_local.address().to_v6().scope_id()));
        unicast_socket_->set_option(option, _error);
        if (_error)
            return;
    }

    boost::asio::socket_base::broadcast option(true);
    unicast_socket_->set_option(option, _error);
    if (_error)
        return;

    const int its_udp_recv_buffer_size = configuration_->get_udp_receive_buffer_size();
    unicast_socket_->set_option(boost::asio::socket_base::receive_buffer_size(
                                       static_cast<int>(its_udp_recv_buffer_size)), _error);

    if (_error)
        return;

    boost::asio::socket_base::receive_buffer_size its_option;
    unicast_socket_->get_option(its_option, _error);
#ifdef __linux__
    // If regular setting of the buffer size did not work, try to force
    // (requires CAP_NET_ADMIN to be successful)
    if (its_option.value() < 0 || its_option.value() < its_udp_recv_buffer_size) {
        _error.assign(setsockopt(unicast_socket_->native_handle(), SOL_SOCKET, SO_RCVBUFFORCE,
                                 &its_udp_recv_buffer_size, sizeof(its_udp_recv_buffer_size)),
                                 boost::system::generic_category());
        if (!_error) {
            VSOMEIP_INFO << "udp_server_endpoint_impl: SO_RCVBUFFORCE successful.";
        }
        unicast_socket_->get_option(its_option, _error);
    }
#endif
    if (_error)
        return;

    local_ = _local;
    local_port_ = _local.port();

    this->max_message_size_ = VSOMEIP_MAX_UDP_MESSAGE_SIZE;
    this->queue_limit_ = configuration_->get_endpoint_queue_limit(
                                                 configuration_->get_unicast_address().to_string(),
                                                 local_port_);
}

void udp_server_endpoint_impl::start() {
    is_stopped_ = false;
    receive();
}

void udp_server_endpoint_impl::stop() {
    server_endpoint_impl::stop();
    is_stopped_ = true;

    {
        std::scoped_lock its_lock {unicast_mutex_};

        if (unicast_socket_->is_open()) {
            boost::system::error_code its_error;
            unicast_socket_->cancel(its_error);
        }
    }

    {
        std::scoped_lock its_lock {multicast_mutex_};
        if (multicast_socket_ && multicast_socket_->is_open()) {
            boost::system::error_code its_error;
            multicast_socket_->cancel(its_error);
        }

        for (auto& its_joined_address : joined_)
            its_joined_address.second = false;
    }

    tp_reassembler_->stop();
}

void udp_server_endpoint_impl::shutdown_and_close() {
    {
        std::lock_guard<std::mutex> its_lock(unicast_mutex_);
        unicast_shutdown_and_close_unlocked();
    }

    {
        std::lock_guard<std::recursive_mutex> its_lock(multicast_mutex_);
        multicast_shutdown_and_close_unlocked();
    }
}

void udp_server_endpoint_impl::unicast_shutdown_and_close_unlocked() {
    boost::system::error_code its_error;
    unicast_socket_->shutdown(socket_type::shutdown_both, its_error);
    unicast_socket_->close(its_error);
}

void udp_server_endpoint_impl::multicast_shutdown_and_close_unlocked() {
    if (!multicast_socket_) {
        return;
    }
    boost::system::error_code its_error;
    multicast_socket_->shutdown(socket_type::shutdown_both, its_error);
    multicast_socket_->close(its_error);
}

void udp_server_endpoint_impl::receive() {
    receive_unicast();
}

void udp_server_endpoint_impl::receive_unicast() {

    std::lock_guard<std::mutex> its_lock(unicast_mutex_);

    if (unicast_socket_->is_open()) {
        unicast_socket_->async_receive_from(
                boost::asio::buffer(&unicast_recv_buffer_[0], max_message_size_),
            unicast_remote_,
            std::bind(
                &udp_server_endpoint_impl::on_unicast_received,
                std::dynamic_pointer_cast<
                    udp_server_endpoint_impl >(shared_from_this()),
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
}

//
// receive_multicast is called with multicast_mutex_ being hold
//
void udp_server_endpoint_impl::receive_multicast(uint8_t _multicast_id) {

    if (_multicast_id == multicast_id_ && multicast_socket_ && multicast_socket_->is_open()) {
        auto its_storage = std::make_shared<udp_endpoint_receive_op::storage>(
            multicast_mutex_,
            multicast_socket_,
            multicast_remote_,
            std::bind(
                &udp_server_endpoint_impl::on_multicast_received,
                std::dynamic_pointer_cast<
                    udp_server_endpoint_impl >(shared_from_this()),
                std::placeholders::_1,
                std::placeholders::_2,
                std::placeholders::_3,
                std::placeholders::_4
            ),
            &multicast_recv_buffer_[0],
            max_message_size_,
            _multicast_id,
            is_v4_,
            boost::asio::ip::address(),
            std::numeric_limits<std::size_t>::min()
        );
        multicast_socket_->async_wait(socket_type::wait_read, udp_endpoint_receive_op::receive_cb(its_storage));
    }
}

bool udp_server_endpoint_impl::send_to(
    const std::shared_ptr<endpoint_definition> _target,
    const byte_t *_data, uint32_t _size) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    endpoint_type its_target(_target->get_address(), _target->get_port());
    return send_intern(its_target, _data, _size);
}

bool udp_server_endpoint_impl::send_error(
    const std::shared_ptr<endpoint_definition> _target,
    const byte_t *_data, uint32_t _size) {

    bool ret(false);
    std::lock_guard<std::mutex> its_lock(mutex_);
    const endpoint_type its_target(_target->get_address(), _target->get_port());
    const auto its_target_iterator(find_or_create_target_unlocked(its_target));
    auto& its_data = its_target_iterator->second;

    if (check_message_size(nullptr, _size, its_target) == endpoint_impl::cms_ret_e::MSG_OK &&
        check_queue_limit(_data, _size, its_data)) {
        its_data.queue_.emplace_back(
                std::make_pair(std::make_shared<message_buffer_t>(_data, _data + _size), 0));
        its_data.queue_size_ += _size;

        if (!its_data.is_sending_) { // no writing in progress
            (void)send_queued(its_target_iterator);
        }
        ret = true;
    }
    return ret;
}

bool udp_server_endpoint_impl::send_queued(
        const target_data_iterator_type _it) {

    std::lock_guard<std::mutex> its_last_sent_lock(last_sent_mutex_);
    std::lock_guard<std::mutex> its_unicast_lock(unicast_mutex_);

    const auto its_entry = _it->second.queue_.front();
#if 0
    std::stringstream msg;
    msg << "usei::sq(" << _queue_iterator->first.address().to_string() << ":"
        << _queue_iterator->first.port() << "): ";
    for (std::size_t i = 0; i < its_buffer->size(); ++i)
        msg << std::hex << std::setw(2) << std::setfill('0')
            << (int)(*its_entry.first)[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif

    // Check whether we need to wait (SOME/IP-TP separation time)
    if (its_entry.second > 0) {
        if (last_sent_ != std::chrono::steady_clock::time_point()) {
            const auto its_elapsed
                = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - last_sent_).count();
            if (its_entry.second > its_elapsed)
                std::this_thread::sleep_for(
                        std::chrono::microseconds(its_entry.second - its_elapsed));
        }
        last_sent_ = std::chrono::steady_clock::now();
    } else {
        last_sent_ = std::chrono::steady_clock::time_point();
    }

    _it->second.is_sending_ = true;
    unicast_socket_->async_send_to(
            boost::asio::buffer(*its_entry.first), _it->first,
            [this, _it, its_entry](boost::system::error_code const& _error, std::size_t _bytes) {
                if (!_error && on_unicast_sent_ && !_it->first.address().is_multicast()) {
                    on_unicast_sent_(&(its_entry.first)->at(0), static_cast<uint32_t>(_bytes),
                                     _it->first.address());
                }
                send_cbk(_it->first, _error, _bytes);
            });
    return false;
}

void udp_server_endpoint_impl::get_configured_times_from_endpoint(
        service_t _service, method_t _method,
        std::chrono::nanoseconds *_debouncing,
        std::chrono::nanoseconds *_maximum_retention) const {

    configuration_->get_configured_timing_responses(_service,
            udp_server_endpoint_base_impl::local_.address().to_string(),
            udp_server_endpoint_base_impl::local_.port(), _method,
            _debouncing, _maximum_retention);
}

//
// Both is_joined - methods must be called with multicast_mutex_ being hold!
//
bool udp_server_endpoint_impl::is_joined(const std::string &_address) const {

    return (joined_.find(_address) != joined_.end());
}

bool udp_server_endpoint_impl::is_joined(
        const std::string &_address, bool& _received) const {

    const auto found_address = joined_.find(_address);
    if (found_address != joined_.end()) {
        _received = found_address->second;
    } else {
        _received = false;
    }

    return (found_address != joined_.end());
}

void udp_server_endpoint_impl::join(const std::string &_address) {

    std::lock_guard<std::recursive_mutex> its_lock(multicast_mutex_);
    join_unlocked(_address);
}

void udp_server_endpoint_impl::join_unlocked(const std::string &_address) {

    bool has_received(false);

    //
    // join_func must be called with multicast_mutex_ being hold!
    //
    auto join_func = [this](const std::string &_address) {
        try {
            VSOMEIP_DEBUG << "Joining to multicast group " << _address
                    << " from " << local_.address().to_string();

            auto its_endpoint_host = endpoint_host_.lock();
            if (its_endpoint_host) {
                multicast_option_t its_join_option { shared_from_this(), true,
                    boost::asio::ip::make_address(_address) };
                its_endpoint_host->add_multicast_option(its_join_option);
            }

            joined_[_address] = false;
        } catch (const std::exception &e) {
            VSOMEIP_ERROR << "udp_server_endpoint_impl::join" << ":" << e.what()
                          << " address: " << _address;
        }
    };

    if (!is_joined(_address, has_received)) {
        join_func(_address);
    } else if (!has_received) {
        // joined the multicast group but didn't receive a event yet -> rejoin
        leave_unlocked(_address);
        join_func(_address);
    }
}

void udp_server_endpoint_impl::leave(const std::string &_address) {

    std::lock_guard<std::recursive_mutex> its_lock(multicast_mutex_);
    leave_unlocked(_address);
}

void udp_server_endpoint_impl::leave_unlocked(const std::string &_address) {

    try {
        if (is_joined(_address)) {
            VSOMEIP_DEBUG << "Leaving the multicast group " << _address
                    << " from " << local_.address().to_string();

            if (multicast_socket_) {
                auto its_endpoint_host = endpoint_host_.lock();
                if (its_endpoint_host) {
                    multicast_option_t its_leave_option { shared_from_this(),
                    false, boost::asio::ip::make_address(_address) };
                    its_endpoint_host->add_multicast_option(its_leave_option);
                }
            }

            joined_.erase(_address);
        }
    }
    catch (const std::exception &e) {
        VSOMEIP_ERROR << __func__ << ":" << e.what()
                      << " address: " << _address;
    }
}

void udp_server_endpoint_impl::add_default_target(
        service_t _service, const std::string &_address, uint16_t _port) {
    std::lock_guard<std::mutex> its_lock(default_targets_mutex_);
    endpoint_type its_endpoint(
            boost::asio::ip::address::from_string(_address), _port);
    default_targets_[_service] = its_endpoint;
}

void udp_server_endpoint_impl::remove_default_target(service_t _service) {
    std::lock_guard<std::mutex> its_lock(default_targets_mutex_);
    default_targets_.erase(_service);
}

bool udp_server_endpoint_impl::get_default_target(service_t _service,
        udp_server_endpoint_impl::endpoint_type &_target) const {
    std::lock_guard<std::mutex> its_lock(default_targets_mutex_);
    bool is_valid(false);
    auto find_service = default_targets_.find(_service);
    if (find_service != default_targets_.end()) {
        _target = find_service->second;
        is_valid = true;
    }
    return is_valid;
}

std::uint16_t udp_server_endpoint_impl::get_local_port() const {
    return local_port_;
}

void udp_server_endpoint_impl::set_local_port(std::uint16_t _port) {
    (void)_port;
}

void udp_server_endpoint_impl::on_unicast_received(
        boost::system::error_code const &_error,
        std::size_t _bytes) {

    if (is_stopped_
            || _error == boost::asio::error::eof
            || _error == boost::asio::error::connection_reset) {
        shutdown_and_close();
    } else if (_error != boost::asio::error::operation_aborted) {
        {
            // By locking the multicast mutex here it is ensured that unicast
            // & multicast messages are not processed in parallel. This aligns
            // the behavior of endpoints with one and two active sockets.
            std::lock_guard<std::recursive_mutex> its_lock(multicast_mutex_);
            on_message_received(_error, _bytes, false,
                    unicast_remote_, unicast_recv_buffer_);
        }
        receive_unicast();
    }
}

void udp_server_endpoint_impl::on_multicast_received(
        boost::system::error_code const &_error,
        std::size_t _bytes,
        uint8_t _multicast_id,
        const boost::asio::ip::address &_destination) {

    std::lock_guard<std::recursive_mutex> its_lock(multicast_mutex_);
    if (is_stopped_
            || _error == boost::asio::error::eof
            || _error == boost::asio::error::connection_reset) {
        shutdown_and_close();
    } else if (_error != boost::asio::error::operation_aborted) {

        if (multicast_remote_.address() != local_.address()) {
            if (is_same_subnet(multicast_remote_.address())) {
                auto find_joined = joined_.find(_destination.to_string());
                if (find_joined != joined_.end())
                    find_joined->second = true;

                on_message_received(_error, _bytes, true, multicast_remote_,
                                    multicast_recv_buffer_);
            }
        } else if (receive_own_multicast_messages_ && on_sent_multicast_received_) {
            on_sent_multicast_received_(&multicast_recv_buffer_[0], static_cast<uint32_t>(_bytes),
                                        boost::asio::ip::address());
        }

        receive_multicast(_multicast_id);
    }
}

void udp_server_endpoint_impl::on_message_received(
        boost::system::error_code const &_error, std::size_t _bytes,
        bool _is_multicast,
        endpoint_type const &_remote,
        message_buffer_t const &_buffer) {
#if 0
    std::stringstream msg;
    msg << "usei::rcb(" << _error.message() << "): ";
    for (std::size_t i = 0; i < _bytes; ++i)
        msg << std::hex << std::setw(2) << std::setfill('0')
            << (int) _buffer[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    std::shared_ptr<routing_host> its_host = routing_host_.lock();

    if (its_host) {
        if (!_error && 0 < _bytes) {
            std::size_t remaining_bytes = _bytes;
            std::size_t i = 0;
            const boost::asio::ip::address its_remote_address(_remote.address());
            const std::uint16_t its_remote_port(_remote.port());
            do {
                uint64_t read_message_size
                    = utility::get_message_size(&_buffer[i],
                            remaining_bytes);
                if (read_message_size > MESSAGE_SIZE_UNLIMITED) {
                    VSOMEIP_ERROR << "Message size exceeds allowed maximum!";
                    return;
                }
                uint32_t current_message_size = static_cast<uint32_t>(read_message_size);
                if (current_message_size > VSOMEIP_SOMEIP_HEADER_SIZE &&
                        current_message_size <= remaining_bytes) {
                    if (remaining_bytes - current_message_size > remaining_bytes) {
                        VSOMEIP_ERROR << "buffer underflow in udp client endpoint ~> abort!";
                        return;
                    } else if (current_message_size > VSOMEIP_RETURN_CODE_POS &&
                        (_buffer[i + VSOMEIP_PROTOCOL_VERSION_POS] != VSOMEIP_PROTOCOL_VERSION ||
                         !utility::is_valid_message_type(tp::tp::tp_flag_unset(_buffer[i + VSOMEIP_MESSAGE_TYPE_POS])) ||
                         !utility::is_valid_return_code(static_cast<return_code_e>(_buffer[i + VSOMEIP_RETURN_CODE_POS])) ||
                         (tp::tp::tp_flag_is_set(_buffer[i + VSOMEIP_MESSAGE_TYPE_POS]) && get_local_port() == configuration_->get_sd_port())
                        )) {
                        if (_buffer[i + VSOMEIP_PROTOCOL_VERSION_POS] != VSOMEIP_PROTOCOL_VERSION) {
                            VSOMEIP_ERROR << "use: Wrong protocol version: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t(_buffer[i + VSOMEIP_PROTOCOL_VERSION_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                            // ensure to send back a message w/ wrong protocol version
                            its_host->on_message(&_buffer[i],
                                                 VSOMEIP_SOMEIP_HEADER_SIZE + 8, this,
                                                 _is_multicast,
                                                 VSOMEIP_ROUTING_CLIENT,
                                                 nullptr,
                                                 its_remote_address, its_remote_port);
                        } else if (!utility::is_valid_message_type(tp::tp::tp_flag_unset(
                                _buffer[i + VSOMEIP_MESSAGE_TYPE_POS]))) {
                            VSOMEIP_ERROR << "use: Invalid message type: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t(_buffer[i + VSOMEIP_MESSAGE_TYPE_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                        } else if (!utility::is_valid_return_code(static_cast<return_code_e>(
                                _buffer[i + VSOMEIP_RETURN_CODE_POS]))) {
                            VSOMEIP_ERROR << "use: Invalid return code: 0x"
                                    << std::hex << std::setw(2) << std::setfill('0')
                                    << std::uint32_t(_buffer[i + VSOMEIP_RETURN_CODE_POS])
                                    << " local: " << get_address_port_local()
                                    << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                        } else if (tp::tp::tp_flag_is_set(_buffer[i + VSOMEIP_MESSAGE_TYPE_POS])
                            && get_local_port() == configuration_->get_sd_port()) {
                            VSOMEIP_WARNING << "use: Received a SomeIP/TP message on SD port:"
                                    << " local: " << get_address_port_local()
                                    << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                        }
                        return;
                    }
                    remaining_bytes -= current_message_size;
                    const service_t its_service = bithelper::read_uint16_be(&_buffer[i + VSOMEIP_SERVICE_POS_MIN]);

                    if (utility::is_request(
                            _buffer[i + VSOMEIP_MESSAGE_TYPE_POS])) {
                        const client_t its_client = bithelper::read_uint16_be(&_buffer[i + VSOMEIP_CLIENT_POS_MIN]);
                        if (its_client != MAGIC_COOKIE_CLIENT) {
                            const session_t its_session = bithelper::read_uint16_be(&_buffer[i + VSOMEIP_SESSION_POS_MIN]);
                            clients_mutex_.lock();
                            clients_[its_client][its_session] = _remote;
                            clients_mutex_.unlock();
                        }
                    }
                    if (tp::tp::tp_flag_is_set(_buffer[i + VSOMEIP_MESSAGE_TYPE_POS])) {
                        const method_t its_method = bithelper::read_uint16_be(&_buffer[i + VSOMEIP_METHOD_POS_MIN]);
                        instance_t its_instance = this->get_instance(its_service);

                        if (its_instance != ANY_INSTANCE) {
                            if (!tp_segmentation_enabled(its_service, its_instance, its_method)) {
                                VSOMEIP_WARNING << "use: Received a SomeIP/TP message for service: 0x" << std::hex << its_service
                                        << " method: 0x" << its_method << " which is not configured for TP:"
                                        << " local: " << get_address_port_local()
                                        << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                                return;
                            }
                        }
                        const auto res = tp_reassembler_->process_tp_message(
                                &_buffer[i], current_message_size,
                                its_remote_address, its_remote_port);
                        if (res.first) {
                            if (utility::is_request(res.second[VSOMEIP_MESSAGE_TYPE_POS])) {
                                const client_t its_client = bithelper::read_uint16_be(&res.second[VSOMEIP_CLIENT_POS_MIN]);
                                if (its_client != MAGIC_COOKIE_CLIENT) {
                                    const session_t its_session = bithelper::read_uint16_be(&res.second[VSOMEIP_SESSION_POS_MIN]);
                                    std::lock_guard<std::mutex> its_client_lock(clients_mutex_);
                                    clients_[its_client][its_session] = _remote;
                                }
                            }
                            its_host->on_message(&res.second[0],
                                    static_cast<std::uint32_t>(res.second.size()),
                                    this, _is_multicast, VSOMEIP_ROUTING_CLIENT,
                                    nullptr,
                                    its_remote_address, its_remote_port);
                        }
                    } else {
                        if (its_service != VSOMEIP_SD_SERVICE ||
                            (current_message_size > VSOMEIP_SOMEIP_HEADER_SIZE &&
                                    current_message_size >= remaining_bytes)) {
                            its_host->on_message(&_buffer[i],
                                    current_message_size, this, _is_multicast,
                                    VSOMEIP_ROUTING_CLIENT,
                                    nullptr,
                                    its_remote_address, its_remote_port);
                        } else {
                            //ignore messages for service discovery with shorter SomeIP length
                            VSOMEIP_ERROR << "Received an unreliable vSomeIP SD message with too short length field"
                                    << " local: " << get_address_port_local()
                                    << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                        }
                    }
                    i += current_message_size;
                } else {
                    VSOMEIP_ERROR << "Received an unreliable vSomeIP message with bad length field"
                            << " local: " << get_address_port_local()
                            << " remote: " << its_remote_address << ":" << std::dec << its_remote_port;
                    if (remaining_bytes > VSOMEIP_SERVICE_POS_MAX) {
                        service_t its_service = bithelper::read_uint16_be(&_buffer[VSOMEIP_SERVICE_POS_MIN]);
                        if (its_service != VSOMEIP_SD_SERVICE) {
                            if (read_message_size == 0) {
                                VSOMEIP_ERROR << "Ignoring unreliable vSomeIP message with SomeIP message length 0!";
                            } else {
                                auto its_endpoint_host = endpoint_host_.lock();
                                if (its_endpoint_host) {
                                    its_endpoint_host->on_error(&_buffer[i],
                                            (uint32_t)remaining_bytes, this,
                                            its_remote_address, its_remote_port);
                                }
                            }
                        }
                    }
                    remaining_bytes = 0;
                }
            } while (remaining_bytes > 0);
        }
    }
}

bool udp_server_endpoint_impl::is_same_subnet(const boost::asio::ip::address &_address) const {
    bool is_same(true);

    if (_address.is_v4()) {
        boost::asio::ip::network_v4 its_network(local_.address().to_v4(), netmask_.to_v4());
        boost::asio::ip::address_v4_range its_hosts = its_network.hosts();
        is_same = (its_hosts.find(_address.to_v4()) != its_hosts.end());
    } else {
        boost::asio::ip::network_v6 its_network(local_.address().to_v6(), prefix_);
        boost::asio::ip::address_v6_range its_hosts = its_network.hosts();
        is_same = (its_hosts.find(_address.to_v6()) != its_hosts.end());
    }

    return is_same;
}

void udp_server_endpoint_impl::print_status() {
    std::lock_guard<std::mutex> its_lock(mutex_);

    VSOMEIP_INFO << "status use: " << std::dec << local_port_
            << " number targets: " << std::dec << targets_.size()
            << " recv_buffer: "
            << std::dec << unicast_recv_buffer_.capacity()
            << " multicast_recv_buffer: "
            << std::dec << multicast_recv_buffer_.capacity();

    for (const auto &c : targets_) {
        std::size_t its_data_size(0);
        std::size_t its_queue_size(0);
        its_queue_size = c.second.queue_.size();
        its_data_size = c.second.queue_size_;

        boost::system::error_code ec;
        VSOMEIP_INFO << "status use: client: "
                << c.first.address().to_string(ec) << ":"
                << std::dec << c.first.port()
                << " queue: " << std::dec << its_queue_size
                << " data: " << std::dec << its_data_size;
    }
}

std::string udp_server_endpoint_impl::get_remote_information(
        const target_data_iterator_type _it) const {

    boost::system::error_code ec;
    return _it->first.address().to_string(ec) + ":"
            + std::to_string(_it->first.port());
}

std::string udp_server_endpoint_impl::get_remote_information(
        const endpoint_type& _remote) const {

    boost::system::error_code ec;
    return _remote.address().to_string(ec) + ":"
            + std::to_string(_remote.port());
}

bool udp_server_endpoint_impl::is_reliable() const {
    return false;
}

std::string udp_server_endpoint_impl::get_address_port_local() const {

    std::lock_guard<std::mutex> its_lock(unicast_mutex_);
    std::string its_address_port;
    its_address_port.reserve(21);
    boost::system::error_code ec;
    if (unicast_socket_->is_open()) {
        endpoint_type its_local_endpoint = unicast_socket_->local_endpoint(ec);
        if (!ec) {
            its_address_port += its_local_endpoint.address().to_string(ec);
            its_address_port += ":";
            its_address_port += std::to_string(its_local_endpoint.port());
        }
    }
    return its_address_port;
}

bool udp_server_endpoint_impl::tp_segmentation_enabled(
        service_t _service, instance_t _instance, method_t _method) const {

    return configuration_->is_tp_service(_service, _instance, _method);
}

void
udp_server_endpoint_impl::set_multicast_option(const boost::asio::ip::address& _address,
                                               bool _is_join, boost::system::error_code &_error) {
    std::scoped_lock its_lock {multicast_mutex_};
    if (_is_join) {
        // If the multicast socket does not yet exist, create it.
        if (!multicast_socket_) {
            multicast_socket_ = std::make_unique<socket_type>(io_, local_.protocol());
            if (!multicast_socket_) {
                _error = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
                return;
            }
        }

        // If the multicast socket is not yet open, open it.
        if (!multicast_socket_->is_open()) {
            multicast_socket_->open(local_.protocol(), _error);
            if (_error) {
                return;
            }
        }

        multicast_socket_->set_option(ip::udp::socket::reuse_address(true), _error);
        if (_error) {
            return;
        }

#ifdef _WIN32
		const char *its_pktinfo_option("0001");
		::setsockopt(multicast_socket_->native_handle(),
				(is_v4_ ? IPPROTO_IP : IPPROTO_IPV6),
				(is_v4_ ? IP_PKTINFO : IPV6_PKTINFO),
				its_pktinfo_option, sizeof(its_pktinfo_option));
#else
		int its_pktinfo_option(1);
		::setsockopt(multicast_socket_->native_handle(),
				(is_v4_ ? IPPROTO_IP : IPPROTO_IPV6),
				(is_v4_ ? IP_PKTINFO : IPV6_RECVPKTINFO),
				&its_pktinfo_option, sizeof(its_pktinfo_option));
#endif
		if (multicast_recv_buffer_.empty())
			multicast_recv_buffer_.resize(VSOMEIP_MAX_UDP_MESSAGE_SIZE, 0);

		if (!multicast_local_) {
			if (is_v4_) {
				multicast_local_ = std::make_unique<endpoint_type>
					(boost::asio::ip::address_v4::any(), local_port_);
			} else { // is_v6
				multicast_local_ = std::make_unique<endpoint_type>
					(boost::asio::ip::address_v6::any(), local_port_);
			}
		}

		multicast_socket_->bind(*multicast_local_, _error);
		if (_error) {
			return;
		}

		const int its_udp_recv_buffer_size =
				configuration_->get_udp_receive_buffer_size();

		multicast_socket_->set_option(boost::asio::socket_base::receive_buffer_size(
				its_udp_recv_buffer_size), _error);
		if (_error) {
			return;
		}
#ifndef _WIN32
		// define socket timeout
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = VSOMEIP_SETSOCKOPT_TIMEOUT_US;

		if (setsockopt(
			multicast_socket_->native_handle(),
			SOL_SOCKET, SO_RCVTIMEO,
			&timeout, sizeof(timeout)) == -1) {
			VSOMEIP_WARNING << __func__
					<< ": unable to setsockopt SO_RCVTIMEO";
		}

		if (setsockopt(
			multicast_socket_->native_handle(),
			SOL_SOCKET, SO_SNDTIMEO,
			&timeout, sizeof(timeout)) == -1) {
			VSOMEIP_WARNING << __func__
					<< ": unable to setsockopt SO_SNDTIMEO";
		}
#endif
		boost::asio::socket_base::receive_buffer_size its_option;
		multicast_socket_->get_option(its_option, _error);
		if (_error) {
			return;
		}
#ifdef __linux__
		// If regular setting of the buffer size did not work, try to force
		// (requires CAP_NET_ADMIN to be successful)
		if (its_option.value() < 0
				|| its_option.value() < its_udp_recv_buffer_size) {
			_error.assign(setsockopt(multicast_socket_->native_handle(),
						SOL_SOCKET, SO_RCVBUFFORCE,
						&its_udp_recv_buffer_size, sizeof(its_udp_recv_buffer_size)),
						boost::system::generic_category());
			if (!_error) {
				VSOMEIP_INFO << "udp_server_endpoint_impl<multicast>: "
						<< "SO_RCVBUFFORCE: successful.";
			}
			multicast_socket_->get_option(its_option, _error);
			if (_error) {
				return;
			}
		}
#endif
		VSOMEIP_INFO << "udp_server_endpoint_impl<multicast>: SO_RCVBUF is: "
					 << std::dec << its_option.value()
					 << " (" << its_udp_recv_buffer_size << ") local port:"
					 << std::dec << local_port_;

		multicast_id_++;
		receive_multicast(multicast_id_);

		boost::asio::ip::multicast::join_group its_join_option;
		{
			std::lock_guard<std::mutex> its_lock(local_mutex_);
			if (is_v4_) {
				its_join_option = boost::asio::ip::multicast::join_group(
						_address.to_v4(),
						local_.address().to_v4());
			} else {
				its_join_option = boost::asio::ip::multicast::join_group(
						_address.to_v6(),
						static_cast<unsigned int>(local_.address().to_v6().scope_id()));
			}
		}
		multicast_socket_->set_option(its_join_option, _error);

		if (!_error) {
			std::lock_guard<std::recursive_mutex> its_guard(multicast_mutex_);
			joined_[_address.to_string()] = false;
			joined_group_ = true;
		}
    } else if (multicast_socket_ && multicast_socket_->is_open()) {
        boost::asio::ip::multicast::leave_group its_leave_option(_address);
        multicast_socket_->set_option(its_leave_option, _error);

        if (!_error) {
            joined_.erase(_address.to_string());

            if (0 == joined_.size()) {
                joined_group_ = false;

                multicast_socket_->cancel(_error);

                multicast_socket_.reset();
                multicast_local_.reset(nullptr);
            }
        }
    }
}

void udp_server_endpoint_impl::set_unicast_sent_callback(const on_unicast_sent_cbk_t& _cbk) {
    on_unicast_sent_ = _cbk;
}

void udp_server_endpoint_impl::set_sent_multicast_received_callback(
        const on_sent_multicast_received_cbk_t& _cbk) {
    on_sent_multicast_received_ = _cbk;
}

void udp_server_endpoint_impl::set_receive_own_multicast_messages(bool value) {
    receive_own_multicast_messages_ = value;
}

bool udp_server_endpoint_impl::is_joining() const {

    std::lock_guard<std::recursive_mutex> its_lock(multicast_mutex_);
    return !joined_.empty();
}

} // namespace vsomeip_v3
