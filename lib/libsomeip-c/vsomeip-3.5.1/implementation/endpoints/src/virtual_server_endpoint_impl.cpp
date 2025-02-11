// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/virtual_server_endpoint_impl.hpp"

#include <vsomeip/constants.hpp>
#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

virtual_server_endpoint_impl::virtual_server_endpoint_impl(const std::string& _address,
                                                           uint16_t _port, bool _reliable,
                                                           boost::asio::io_context& _io) :

    address_(_address),
    port_(_port), reliable_(_reliable), io_(_io) { }

virtual_server_endpoint_impl::~virtual_server_endpoint_impl() {
}

void virtual_server_endpoint_impl::start() {
}

void virtual_server_endpoint_impl::prepare_stop(const endpoint::prepare_stop_handler_t &_handler,
                                                service_t _service) {
    (void)_service;

    auto ptr = shared_from_this();
    io_.post([ptr, _handler]() { _handler(ptr); });
}

void virtual_server_endpoint_impl::stop() {
}

bool virtual_server_endpoint_impl::is_established() const {
    return false;
}

bool virtual_server_endpoint_impl::is_established_or_connected() const {
    return false;
}

void virtual_server_endpoint_impl::set_established(bool _established) {
    (void) _established;
}

void virtual_server_endpoint_impl::set_connected(bool _connected) {
    (void) _connected;
}

bool virtual_server_endpoint_impl::send(const byte_t *_data, uint32_t _size) {
    (void)_data;
    (void)_size;
    return false;
}

bool virtual_server_endpoint_impl::send_to(
        const std::shared_ptr<endpoint_definition> _target,
        const byte_t *_data, uint32_t _size) {
    (void)_target;
    (void)_data;
    (void)_size;
    return false;
}

bool virtual_server_endpoint_impl::send_error(
        const std::shared_ptr<endpoint_definition> _target,
        const byte_t *_data, uint32_t _size) {
    (void)_target;
    (void)_data;
    (void)_size;
    return false;
}


void virtual_server_endpoint_impl::enable_magic_cookies() {
}

void virtual_server_endpoint_impl::receive() {
}

void virtual_server_endpoint_impl::add_default_target(
        service_t _service,
        const std::string &_address, uint16_t _port) {
    (void)_service;
    (void)_address;
    (void)_port;
}

void virtual_server_endpoint_impl::remove_default_target(
        service_t _service) {
    (void)_service;
}

void virtual_server_endpoint_impl::remove_stop_handler(
        service_t) {
}

bool virtual_server_endpoint_impl::get_remote_address(
        boost::asio::ip::address &_address) const {
    (void)_address;
    return false;
}

std::uint16_t virtual_server_endpoint_impl::get_local_port() const {
    return port_;
}

void virtual_server_endpoint_impl::set_local_port(std::uint16_t _port) {
    port_ = _port;
}

std::uint16_t virtual_server_endpoint_impl::get_remote_port() const {
    return ILLEGAL_PORT;
}

bool virtual_server_endpoint_impl::is_reliable() const {
    return reliable_;
}

bool virtual_server_endpoint_impl::is_local() const {
    return true;
}

void virtual_server_endpoint_impl::restart(bool _force) {
    (void)_force;
}

void virtual_server_endpoint_impl::register_error_handler(
        const error_handler_t &_handler) {
    (void)_handler;
}

void virtual_server_endpoint_impl::print_status() {

}

size_t virtual_server_endpoint_impl::get_queue_size() const {
    return 0;
}
} // namespace vsomeip_v3
