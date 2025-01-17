// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SERVER_ENDPOINT_IMPL_HPP_
#define VSOMEIP_V3_SERVER_ENDPOINT_IMPL_HPP_

#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include <boost/array.hpp>

#include "buffer.hpp"
#include "endpoint_impl.hpp"
#include "tp.hpp"
#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {

template<typename Protocol>
class server_endpoint_impl: public endpoint_impl<Protocol>,
        public std::enable_shared_from_this<server_endpoint_impl<Protocol> > {
public:
    typedef typename Protocol::socket socket_type;
    typedef typename Protocol::endpoint endpoint_type;
    struct endpoint_data_type {
        endpoint_data_type(boost::asio::io_context &_io)
            : train_(std::make_shared<train>()),
              dispatch_timer_(std::make_shared<boost::asio::steady_timer>(_io)),
              has_last_departure_(false),
              queue_size_(0),
              is_sending_(false),
              sent_timer_(_io),
              io_(_io) {
        }

        endpoint_data_type(const endpoint_data_type &&_source)
            : train_(_source.train_),
              dispatch_timer_(std::make_shared<boost::asio::steady_timer>(_source.io_)),
              has_last_departure_(_source.has_last_departure_),
              queue_(_source.queue_),
              queue_size_(_source.queue_size_),
              is_sending_(_source.is_sending_),
              sent_timer_(_source.io_),
              io_(_source.io_) {
        }

        std::shared_ptr<train> train_;
        std::map<std::chrono::steady_clock::time_point,
            std::deque<std::shared_ptr<train> > > dispatched_trains_;
        std::shared_ptr<boost::asio::steady_timer> dispatch_timer_;
        std::chrono::steady_clock::time_point last_departure_;
        bool has_last_departure_;

        std::deque<std::pair<message_buffer_ptr_t, uint32_t> > queue_;
        std::size_t queue_size_;

        bool is_sending_;
        boost::asio::steady_timer sent_timer_;

        boost::asio::io_context &io_;
    };

    typedef typename std::map<endpoint_type, endpoint_data_type> target_data_type;
    typedef typename target_data_type::iterator target_data_iterator_type;

    server_endpoint_impl(const std::shared_ptr<endpoint_host>& _endpoint_host,
                         const std::shared_ptr<routing_host>& _routing_host,
                         boost::asio::io_context &_io,
                         const std::shared_ptr<configuration>& _configuration);
    virtual ~server_endpoint_impl() = default;

    virtual void init(const endpoint_type& _local, boost::system::error_code& _error) = 0;
    virtual void stop();

    bool is_client() const;
    void restart(bool _force);
    bool is_established() const;
    bool is_established_or_connected() const;
    void set_established(bool _established);
    void set_connected(bool _connected);
    bool send(const uint8_t *_data, uint32_t _size);
    bool send(const std::vector<byte_t>& _cmd_header, const byte_t *_data,
              uint32_t _size);

    void prepare_stop(const endpoint::prepare_stop_handler_t &_handler,
                      service_t _service);
    bool flush(endpoint_type _it);

    size_t get_queue_size() const;

    virtual bool is_reliable() const = 0;
    virtual std::uint16_t get_local_port() const = 0;
    virtual void set_local_port(uint16_t _port) = 0;

public:
    void connect_cbk(boost::system::error_code const &_error);
    void send_cbk(const endpoint_type _key,
                  boost::system::error_code const &_error, std::size_t _bytes);
    void flush_cbk(endpoint_type _key,
            const boost::system::error_code &_error_code);
    void remove_stop_handler(service_t _service);

protected:
    virtual bool send_intern(endpoint_type _target, const byte_t *_data,
                             uint32_t _port);
    virtual bool send_queued(const target_data_iterator_type _it) = 0;
    virtual void get_configured_times_from_endpoint(
            service_t _service, method_t _method,
            std::chrono::nanoseconds *_debouncing,
            std::chrono::nanoseconds *_maximum_retention) const = 0;

    virtual bool get_default_target(service_t _service,
            endpoint_type &_target) const = 0;

    virtual void print_status() = 0;

    typename endpoint_impl<Protocol>::cms_ret_e check_message_size(
            const std::uint8_t * const _data, std::uint32_t _size,
            const endpoint_type &_target);
    bool check_queue_limit(const uint8_t *_data, std::uint32_t _size,
                           endpoint_data_type &_endpoint_data) const;
    bool queue_train(const target_data_iterator_type _it,
            const std::shared_ptr<train> &_train);

    void send_segments(const tp::tp_split_messages_t &_segments,
            std::uint32_t _separation_time, const endpoint_type &_target);

    target_data_iterator_type find_or_create_target_unlocked(endpoint_type _target);

protected:
    std::mutex clients_mutex_;
    std::map<client_t, std::map<session_t, endpoint_type> > clients_;

    target_data_type targets_;

    std::map<service_t, endpoint::prepare_stop_handler_t> prepare_stop_handlers_;

    mutable std::mutex mutex_;

private:
    virtual std::string get_remote_information(
            const target_data_iterator_type _queue_iterator) const = 0;
    virtual std::string get_remote_information(
            const endpoint_type& _remote) const = 0;
    virtual bool tp_segmentation_enabled(service_t _service,
                                         instance_t _instance,
                                         method_t _method) const;

    void schedule_train(endpoint_data_type &_target);
    void update_last_departure(endpoint_data_type &_data);

    void start_dispatch_timer(target_data_iterator_type _it,
            const std::chrono::steady_clock::time_point &_now);
    void cancel_dispatch_timer(target_data_iterator_type _it);

    void recalculate_queue_size(endpoint_data_type &_data) const;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SERVER_ENDPOINT_IMPL_HPP_
