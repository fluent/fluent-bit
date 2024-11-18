// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <cstring>
#include <limits>

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include "../include/routing_info_entry.hpp"

namespace vsomeip_v3 {
namespace protocol {

routing_info_entry::routing_info_entry()
    : type_(routing_info_entry_type_e::RIE_UNKNOWN),
      port_(0) {

}

routing_info_entry::routing_info_entry(const routing_info_entry &_source)
    : type_(_source.type_),
      client_(_source.client_),
      address_(_source.address_),
      port_(_source.port_),
      services_(_source.services_) {

}

void
routing_info_entry::serialize(std::vector<byte_t> &_buffer,
        size_t &_index, error_e &_error) const {

    _buffer[_index] = static_cast<byte_t>(type_);
    _index += sizeof(type_);

    // Size is overall size - size field - command type
    size_t its_size = get_size() - sizeof(uint32_t) - 1;
    if (its_size > std::numeric_limits<uint32_t>::max()) {

        _error = error_e::ERROR_MALFORMED;
        return;
    }

    uint32_t its_size32(static_cast<uint32_t>(its_size));
    std::memcpy(&_buffer[_index], &its_size32, sizeof(its_size32));
    _index += sizeof(its_size32);

    uint32_t its_client_size(sizeof(client_));
    if (!address_.is_unspecified()) {
        if (address_.is_v4()) {
            its_client_size += uint32_t(sizeof(boost::asio::ip::address_v4::bytes_type)
                    + sizeof(port_));
        } else {
            its_client_size += uint32_t(sizeof(boost::asio::ip::address_v6::bytes_type)
                    + sizeof(port_));
        }
    }

    if (type_ > routing_info_entry_type_e::RIE_DELETE_CLIENT) {

        std::memcpy(&_buffer[_index], &its_client_size, sizeof(its_client_size));
        _index += sizeof(its_client_size);
    }

    std::memcpy(&_buffer[_index], &client_, sizeof(client_));
    _index += sizeof(client_);

    if (!address_.is_unspecified()) {

        if (address_.is_v4()) {
            std::memcpy(&_buffer[_index], address_.to_v4().to_bytes().data(),
                    sizeof(boost::asio::ip::address_v4::bytes_type));
            _index += sizeof(boost::asio::ip::address_v4::bytes_type);
        } else {
            std::memcpy(&_buffer[_index], address_.to_v6().to_bytes().data(),
                    sizeof(boost::asio::ip::address_v6::bytes_type));
            _index += sizeof(boost::asio::ip::address_v6::bytes_type);
        }
        std::memcpy(&_buffer[_index], &port_, sizeof(port_));
        _index += sizeof(port_);
    }

    if (type_ > routing_info_entry_type_e::RIE_DELETE_CLIENT) {

        its_size = (services_.size() *
            (sizeof(service_t) + sizeof(instance_t) +
             sizeof(major_version_t) + sizeof(minor_version_t)));

        if (its_size > std::numeric_limits<uint32_t>::max()) {

            _error = error_e::ERROR_MALFORMED;
            return;
        }

        its_size32 = static_cast<uint32_t>(its_size);
        std::memcpy(&_buffer[_index], &its_size32, sizeof(its_size32));
        _index += sizeof(its_size32);

        for (const auto &s : services_) {

            std::memcpy(&_buffer[_index], &s.service_, sizeof(s.service_));
            _index += sizeof(s.service_);
            std::memcpy(&_buffer[_index], &s.instance_, sizeof(s.instance_));
            _index += sizeof(s.instance_);
            std::memcpy(&_buffer[_index], &s.major_, sizeof(s.major_));
            _index += sizeof(s.major_);
            std::memcpy(&_buffer[_index], &s.minor_, sizeof(s.minor_));
            _index += sizeof(s.minor_);
        }
    }
}

void
routing_info_entry::deserialize(const std::vector<byte_t> &_buffer,
        size_t &_index, error_e &_error) {

    uint32_t its_size;
    uint32_t its_client_size;

    if (_buffer.size() < _index + sizeof(type_) + sizeof(its_size)
            + sizeof(client_)) {

        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    type_ = static_cast<routing_info_entry_type_e>(_buffer[_index++]);
    if (type_ == routing_info_entry_type_e::RIE_UNKNOWN) {

        _error = error_e::ERROR_MALFORMED;
        return;
    }

    std::memcpy(&its_size, &_buffer[_index], sizeof(its_size));
    _index += sizeof(its_size);

    if (type_ > routing_info_entry_type_e::RIE_DELETE_CLIENT) {
        std::memcpy(&its_client_size, &_buffer[_index], sizeof(its_client_size));
        _index += sizeof(its_client_size);
    } else {
        its_client_size = its_size;
    }

    std::memcpy(&client_, &_buffer[_index], sizeof(client_));
    _index += sizeof(client_);

    if (its_client_size > sizeof(client_)) {

        uint32_t its_address_size = its_client_size
                - uint32_t(sizeof(client_t) + sizeof(port_));

        if (its_address_size == sizeof(boost::asio::ip::address_v4::bytes_type)) {

            boost::asio::ip::address_v4::bytes_type its_array;
            std::memcpy(&its_array, &_buffer[_index], its_array.size());
            address_ = boost::asio::ip::address_v4(its_array);
            _index += its_array.size();

        } else if (its_address_size == sizeof(boost::asio::ip::address_v6::bytes_type)) {

            boost::asio::ip::address_v6::bytes_type its_array;
            std::memcpy(&its_array, &_buffer[_index], its_array.size());
            address_ = boost::asio::ip::address_v6(its_array);
            _index += its_array.size();

        } else {

            _error = error_e::ERROR_MALFORMED;
            return;
        }

        std::memcpy(&port_, &_buffer[_index], sizeof(port_));
        _index += sizeof(port_);
    }

    if (type_ > routing_info_entry_type_e::RIE_DELETE_CLIENT) {

        if (_buffer.size() < _index + sizeof(its_size)) {

            _error = error_e::ERROR_NOT_ENOUGH_BYTES;
            return;
        }

        std::memcpy(&its_size, &_buffer[_index], sizeof(its_size));
        _index += sizeof(its_size);

        if (_buffer.size() < _index + its_size) {

            _error = error_e::ERROR_NOT_ENOUGH_BYTES;
            return;
        }

        size_t its_n = (its_size /
            (sizeof(service_t) + sizeof(instance_t) +
             sizeof(major_version_t) + sizeof(minor_version_t)));

        for (size_t i = 0; i < its_n; i++) {

            service its_service;
            std::memcpy(&its_service.service_, &_buffer[_index], sizeof(its_service.service_));
            _index += sizeof(its_service.service_);
            std::memcpy(&its_service.instance_, &_buffer[_index], sizeof(its_service.instance_));
            _index += sizeof(its_service.instance_);
            its_service.major_ = static_cast<major_version_t>(_buffer[_index]);
            _index += sizeof(its_service.major_);
            std::memcpy(&its_service.minor_, &_buffer[_index], sizeof(its_service.minor_));
            _index += sizeof(its_service.minor_);

            services_.emplace_back(its_service);
        }
    }
}

routing_info_entry_type_e
routing_info_entry::get_type() const {

    return type_;
}

void
routing_info_entry::set_type(routing_info_entry_type_e _type) {

    type_ = _type;
}

size_t
routing_info_entry::get_size() const {

    size_t its_size(ROUTING_INFO_ENTRY_HEADER_SIZE);

    if (!address_.is_unspecified()) {
        if (address_.is_v4()) {
            its_size += (sizeof(boost::asio::ip::address_v4::bytes_type)
                    + sizeof(port_));
        } else {
            its_size += (sizeof(boost::asio::ip::address_v6::bytes_type)
                    + sizeof(port_));
        }
    }

    if (type_ > routing_info_entry_type_e::RIE_DELETE_CLIENT) {
        its_size += sizeof(uint32_t); // size of the client info
        its_size += sizeof(uint32_t); // size of the services array
        its_size += (services_.size() *
                (sizeof(service_t) + sizeof(instance_t) +
                 sizeof(major_version_t) + sizeof(minor_version_t)));
    }

    return its_size;
}

client_t
routing_info_entry::get_client() const {

    return client_;
}

void
routing_info_entry::set_client(client_t _client) {

    client_ = _client;
}

boost::asio::ip::address
routing_info_entry::get_address() const {

    return address_;
}

void
routing_info_entry::set_address(const boost::asio::ip::address &_address) {

    address_ = _address;
}

port_t
routing_info_entry::get_port() const {

    return port_;
}

void
routing_info_entry::set_port(port_t _port) {

    port_ = _port;
}

const std::vector<service> &
routing_info_entry::get_services() const {

    return services_;
}

void
routing_info_entry::add_service(const service &_service) {

    services_.push_back(_service);
}

} // namespace protocol
} // namespace vsomeip
