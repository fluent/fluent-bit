// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_ENDPOINT_IMPL_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <atomic>

#include <boost/asio/steady_timer.hpp>

#include "buffer.hpp"
#include "endpoint.hpp"
#include "../../configuration/include/configuration.hpp"

namespace vsomeip_v3 {

class endpoint_host;
class routing_host;

template<typename Protocol>
class endpoint_impl: public virtual endpoint {
public:
    typedef typename Protocol::endpoint endpoint_type;

    endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                  const std::shared_ptr<routing_host>& _routing_host, boost::asio::io_context& _io,
                  const std::shared_ptr<configuration>& _configuration);
    endpoint_impl(endpoint_impl<Protocol> const&) = delete;
    endpoint_impl(endpoint_impl<Protocol> const&&) = delete;
    virtual ~endpoint_impl() = default;

    void enable_magic_cookies();

    void add_default_target(service_t, const std::string &, uint16_t);
    void remove_default_target(service_t);
    void remove_stop_handler(service_t);

    virtual std::uint16_t get_local_port() const = 0;
    virtual void set_local_port(uint16_t _port) = 0;
    virtual bool is_reliable() const = 0;

    void register_error_handler(const error_handler_t &_error_handler);
    virtual void print_status() = 0;

    virtual size_t get_queue_size() const = 0;

public:
    // required
    virtual bool is_client() const = 0;
    virtual void receive() = 0;
    virtual void restart(bool _force) = 0;

protected:
    uint32_t find_magic_cookie(byte_t *_buffer, size_t _size);
    instance_t get_instance(service_t _service);

protected:
    enum class cms_ret_e : uint8_t {
        MSG_TOO_BIG,
        MSG_OK,
        MSG_WAS_SPLIT
    };

    // Reference to service context
    boost::asio::io_context &io_;

    // References to hosts
    std::weak_ptr<endpoint_host> endpoint_host_;
    std::weak_ptr<routing_host> routing_host_;

    bool is_supporting_magic_cookies_;
    std::atomic<bool> has_enabled_magic_cookies_;

    // Filter configuration
    std::map<service_t, uint8_t> opened_;

    std::uint32_t max_message_size_;

    std::atomic<uint32_t> use_count_;

    std::atomic<bool> sending_blocked_;

    std::mutex local_mutex_;
    endpoint_type local_;

    error_handler_t error_handler_;
    std::mutex error_handler_mutex_;

    configuration::endpoint_queue_limit_t queue_limit_;

    std::shared_ptr<configuration> configuration_;

    bool is_supporting_someip_tp_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_ENDPOINT_IMPL_HPP_
