// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>
#include <memory>
#include <sstream>
#include <limits>
#include <thread>
#include <algorithm>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/ip/udp.hpp>

#include <vsomeip/defines.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/server_endpoint_impl.hpp"
#include "../include/endpoint_definition.hpp"

#include "../../utility/include/bithelper.hpp"
#include "../../utility/include/utility.hpp"
#include "../../service_discovery/include/defines.hpp"

namespace vsomeip_v3 {

template<typename Protocol>
server_endpoint_impl<Protocol>::server_endpoint_impl(
        const std::shared_ptr<endpoint_host>& _endpoint_host,
        const std::shared_ptr<routing_host>& _routing_host,
		boost::asio::io_context &_io,
        const std::shared_ptr<configuration>& _configuration)
    : endpoint_impl<Protocol>(_endpoint_host, _routing_host, _io, _configuration) {
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::prepare_stop(
        const endpoint::prepare_stop_handler_t &_handler, service_t _service) {

    std::lock_guard<std::mutex> its_lock(mutex_);
    std::vector<target_data_iterator_type> its_erased;
    boost::system::error_code ec;

    if (_service == ANY_SERVICE) {
        endpoint_impl<Protocol>::sending_blocked_ = true;
        if (std::all_of(targets_.begin(), targets_.end(),
                        [&](const typename target_data_type::value_type &_t)
                            { return _t.second.queue_.empty(); })) {
            // nothing was queued and all queues are empty -> ensure cbk is called
            auto ptr = this->shared_from_this();
            endpoint_impl<Protocol>::io_.post(
                    [ptr, _handler]() { _handler(ptr); });
        } else {
            prepare_stop_handlers_[_service] = _handler;
        }

        for (auto t = targets_.begin(); t != targets_.end(); t++) {
            auto its_train (t->second.train_);
            // cancel dispatch timer
            t->second.dispatch_timer_->cancel(ec);
            if (its_train->buffer_->size() > 0) {
                if (queue_train(t, its_train))
                    its_erased.push_back(t);
            }
        }
    } else {
        // check if any of the queues contains a message of to be stopped service
        bool found_service_msg(false);
        for (const auto &t : targets_) {
            for (const auto &q : t.second.queue_) {
                const service_t its_service = bithelper::read_uint16_be(&(*q.first)[VSOMEIP_SERVICE_POS_MIN]);
                if (its_service == _service) {
                    found_service_msg = true;
                    break;
                }
            }
            if (found_service_msg) {
                break;
            }
        }
        if (found_service_msg) {
            prepare_stop_handlers_[_service] = _handler;
        } else { // no messages of the to be stopped service are or have been queued
            auto ptr = this->shared_from_this();
            endpoint_impl<Protocol>::io_.post(
                    [ptr, _handler]() { _handler(ptr); });
        }

        for (auto t = targets_.begin(); t != targets_.end(); t++) {
            auto its_train(t->second.train_);
            for (auto const& passenger_iter : its_train->passengers_) {
                if (passenger_iter.first == _service) {
                    // cancel dispatch timer
                    t->second.dispatch_timer_->cancel(ec);
                    // TODO: Queue all(!) trains here...
                    if (queue_train(t, its_train))
                        its_erased.push_back(t);
                    break;
                }
            }
        }
    }

    for (const auto t : its_erased)
        targets_.erase(t);
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::stop() {
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::is_client() const {
    return false;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::restart(bool _force) {
    (void)_force;

	boost::system::error_code its_error;
	this->init(server_endpoint_impl<Protocol>::local_, its_error);
	this->start();
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::is_established() const {
    return true;
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::is_established_or_connected() const {
    return true;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::set_established(bool _established) {
    (void) _established;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::set_connected(bool _connected) {
    (void) _connected;
}

template<typename Protocol>bool server_endpoint_impl<Protocol>::send(const uint8_t *_data,
        uint32_t _size) {
#if 0
    std::stringstream msg;
    msg << "sei::send ";
    for (uint32_t i = 0; i < _size; i++)
        msg << std::hex << std::setw(2) << std::setfill('0') << (int)_data[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    endpoint_type its_target;
    bool is_valid_target(false);

    if (VSOMEIP_SESSION_POS_MAX < _size) {
        std::lock_guard<std::mutex> its_lock(mutex_);

        if(endpoint_impl<Protocol>::sending_blocked_) {
            return false;
        }

        const service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
        const client_t its_client   = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
        const session_t its_session = bithelper::read_uint16_be(&_data[VSOMEIP_SESSION_POS_MIN]);

        clients_mutex_.lock();
        auto found_client = clients_.find(its_client);
        if (found_client != clients_.end()) {
            auto found_session = found_client->second.find(its_session);
            if (found_session != found_client->second.end()) {
                its_target = found_session->second;
                is_valid_target = true;
                found_client->second.erase(its_session);
            } else {
                VSOMEIP_WARNING << "server_endpoint::send: session_id 0x"
                        << std::hex << its_session
                        << " not found for client 0x" << its_client;
                const method_t its_method = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);

                if (its_service == VSOMEIP_SD_SERVICE
                        && its_method == VSOMEIP_SD_METHOD) {
                    VSOMEIP_ERROR << "Clearing clients map as a request was "
                            "received on SD port";
                    clients_.clear();
                    is_valid_target = get_default_target(its_service, its_target);
                }
            }
        } else {
            is_valid_target = get_default_target(its_service, its_target);
        }
        clients_mutex_.unlock();

        if (is_valid_target) {
            is_valid_target = send_intern(its_target, _data, _size);
        }
    }
    return is_valid_target;
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::send(
        const std::vector<byte_t>& _cmd_header, const byte_t *_data,
        uint32_t _size) {
    (void) _cmd_header;
    (void) _data;
    (void) _size;
    return false;
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::send_intern(
        endpoint_type _target, const byte_t *_data, uint32_t _size) {

    switch (check_message_size(_data, _size, _target)) {
        case endpoint_impl<Protocol>::cms_ret_e::MSG_WAS_SPLIT:
            return true;
            break;
        case endpoint_impl<Protocol>::cms_ret_e::MSG_TOO_BIG:
            return false;
            break;
        case endpoint_impl<Protocol>::cms_ret_e::MSG_OK:
        default:
            break;
    }
    if (!prepare_stop_handlers_.empty()) {
        const service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
        if (prepare_stop_handlers_.find(its_service) != prepare_stop_handlers_.end()) {
            const method_t its_method   = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);
            const client_t its_client   = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
            const session_t its_session = bithelper::read_uint16_be(&_data[VSOMEIP_SESSION_POS_MIN]);
            VSOMEIP_WARNING << "server_endpoint::send: Service is stopping, ignoring message: ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_method << "."
                    << std::setw(4) << its_client << "."
                    << std::setw(4) << its_session << "]";
            return false;
        }
    }

    const auto its_target_iterator = find_or_create_target_unlocked(_target);
    auto &its_data(its_target_iterator->second);

    bool must_depart(false);
    auto its_now(std::chrono::steady_clock::now());

#if 0
    std::stringstream msg;
    msg << "sei::send_intern: ";
    for (uint32_t i = 0; i < _size; i++)
    msg << std::hex << std::setw(2) << std::setfill('0') << (int)_data[i] << " ";
    VSOMEIP_DEBUG << msg.str();
#endif
    // STEP 1: Check queue limit
    if (!check_queue_limit(_data, _size, its_data)) {
        return false;
    }

    // STEP 2: Cancel the dispatch timer
    cancel_dispatch_timer(its_target_iterator);

    // STEP 3: Get configured timings
    const service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
    const method_t its_method   = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);

    std::chrono::nanoseconds its_debouncing(0), its_retention(0);
    if (its_service != VSOMEIP_SD_SERVICE && its_method != VSOMEIP_SD_METHOD) {
        get_configured_times_from_endpoint(its_service, its_method,
                &its_debouncing, &its_retention);
    }

    // STEP 4: Check if the passenger enters an empty train
    const std::pair<service_t, method_t> its_identifier
        = std::make_pair(its_service, its_method);
    if (its_data.train_->passengers_.empty()) {
        its_data.train_->departure_ = its_now + its_retention;
    } else {
        if (its_data.train_->passengers_.end()
                != its_data.train_->passengers_.find(its_identifier)) {
            must_depart = true;
        } else {
            // STEP 5: Check whether the current message fits into the current train
            if (its_data.train_->buffer_->size() + _size > endpoint_impl<Protocol>::max_message_size_) {
                must_depart = true;
            } else {
                // STEP 6: Check debouncing time
                if (its_debouncing > its_data.train_->minimal_max_retention_time_) {
                    // train's latest departure would already undershot new
                    // passenger's debounce time
                    must_depart = true;
                } else {
                    if (its_now + its_debouncing > its_data.train_->departure_) {
                        // train departs earlier as the new passenger's debounce
                        // time allows
                        must_depart = true;
                    } else {
                        // STEP 7: Check maximum retention time
                        if (its_retention < its_data.train_->minimal_debounce_time_) {
                            // train's earliest departure would already exceed
                            // the new passenger's retention time.
                            must_depart = true;
                        } else {
                            if (its_now + its_retention < its_data.train_->departure_) {
                                its_data.train_->departure_ = its_now + its_retention;
                            }
                        }
                    }
                }
            }
        }
    }

    // STEP 8: if necessary, send current buffer and create a new one
    if (must_depart) {
        // STEP 8.1: check if debounce time would be undershot here if the train
        // departs. Block sending until train is allowed to depart.
        schedule_train(its_data);

        its_data.train_ = std::make_shared<train>();
        its_data.train_->departure_ = its_now + its_retention;
    }

    // STEP 9: insert current message buffer
    its_data.train_->buffer_->insert(its_data.train_->buffer_->end(), _data, _data + _size);
    its_data.train_->passengers_.insert(its_identifier);
    // STEP 9.1: update the trains minimal debounce time if necessary
    if (its_debouncing < its_data.train_->minimal_debounce_time_) {
        its_data.train_->minimal_debounce_time_ = its_debouncing;
    }
    // STEP 9.2: update the trains minimal maximum retention time if necessary
    if (its_retention < its_data.train_->minimal_max_retention_time_) {
        its_data.train_->minimal_max_retention_time_ = its_retention;
    }

    // STEP 10: restart timer with current departure time
    start_dispatch_timer(its_target_iterator, its_now);

    return true;
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::tp_segmentation_enabled(
        service_t /*_service*/, instance_t /*_instance*/, method_t /*_method*/) const {

    return false;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::send_segments(
        const tp::tp_split_messages_t &_segments, std::uint32_t _separation_time,
        const endpoint_type &_target) {

    if (_segments.size() == 0)
        return;

    const auto its_target_iterator = find_or_create_target_unlocked(_target);
    auto &its_data = its_target_iterator->second;

    auto its_now(std::chrono::steady_clock::now());

    const service_t its_service = bithelper::read_uint16_be(&(*(_segments[0]))[VSOMEIP_SERVICE_POS_MIN]);
    const method_t its_method   = bithelper::read_uint16_be(&(*(_segments[0]))[VSOMEIP_METHOD_POS_MIN]);

    std::chrono::nanoseconds its_debouncing(0), its_retention(0);
    if (its_service != VSOMEIP_SD_SERVICE && its_method != VSOMEIP_SD_METHOD) {
        get_configured_times_from_endpoint(its_service, its_method,
                &its_debouncing, &its_retention);
    }
    // update the trains minimal debounce time if necessary
    if (its_debouncing < its_data.train_->minimal_debounce_time_) {
        its_data.train_->minimal_debounce_time_ = its_debouncing;
    }
    // update the trains minimal maximum retention time if necessary
    if (its_retention < its_data.train_->minimal_max_retention_time_) {
        its_data.train_->minimal_max_retention_time_ = its_retention;
    }
    // We only need to respect the debouncing. There is no need to wait for further
    // messages as we will send several now anyway.
    if (!its_data.train_->passengers_.empty()) {
        schedule_train(its_data);
        its_data.train_ = std::make_shared<train>();
        its_data.train_->departure_ = its_now + its_retention;
    }

    for (const auto &s : _segments) {
        its_data.queue_.emplace_back(s, _separation_time);
        its_data.queue_size_ += s->size();
    }

    if (!its_data.is_sending_ && !its_data.queue_.empty()) { // no writing in progress
        // ignore retention time and send immediately as the train is full anyway
        (void)send_queued(its_target_iterator);
    }
}

template<typename Protocol>
typename server_endpoint_impl<Protocol>::target_data_iterator_type
server_endpoint_impl<Protocol>::find_or_create_target_unlocked(endpoint_type _target) {

    auto its_iterator = targets_.find(_target);
    if (its_iterator == targets_.end()) {
        auto its_result = targets_.emplace(
                std::make_pair(_target, endpoint_data_type(this->io_)));
        its_iterator = its_result.first;
    }

    return its_iterator;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::schedule_train(endpoint_data_type &_data) {

    if (_data.has_last_departure_) {
        if (_data.last_departure_ + _data.train_->minimal_debounce_time_
                > _data.train_->departure_) {
            _data.train_->departure_ = _data.last_departure_
                    + _data.train_->minimal_debounce_time_;
        }
    }

    _data.dispatched_trains_[_data.train_->departure_]
                             .push_back(_data.train_);
}

template<typename Protocol>
typename endpoint_impl<Protocol>::cms_ret_e server_endpoint_impl<Protocol>::check_message_size(
        const std::uint8_t * const _data, std::uint32_t _size,
        const endpoint_type& _target) {
    typename endpoint_impl<Protocol>::cms_ret_e ret(endpoint_impl<Protocol>::cms_ret_e::MSG_OK);
    if (endpoint_impl<Protocol>::max_message_size_ != MESSAGE_SIZE_UNLIMITED
            && _size > endpoint_impl<Protocol>::max_message_size_) {
        if (endpoint_impl<Protocol>::is_supporting_someip_tp_ && _data != nullptr) {
            const service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
            const method_t its_method   = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);
            instance_t its_instance = this->get_instance(its_service);

            if (its_instance != ANY_INSTANCE) {
                if (tp_segmentation_enabled(its_service, its_instance, its_method)) {
                    std::uint16_t its_max_segment_length;
                    std::uint32_t its_separation_time;

                    this->configuration_->get_tp_configuration(
                                its_service, its_instance, its_method, false,
                                its_max_segment_length, its_separation_time);
                    send_segments(tp::tp::tp_split_message(_data, _size,
                            its_max_segment_length), its_separation_time, _target);
                    return endpoint_impl<Protocol>::cms_ret_e::MSG_WAS_SPLIT;
                }
            }
        }
        VSOMEIP_ERROR << "sei::send_intern: Dropping to big message (" << _size
                << " Bytes). Maximum allowed message size is: "
                << endpoint_impl<Protocol>::max_message_size_ << " Bytes.";
        ret = endpoint_impl<Protocol>::cms_ret_e::MSG_TOO_BIG;
    }
    return ret;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::recalculate_queue_size(endpoint_data_type &_data) const {
    _data.queue_size_ = 0;
    for (const auto &q : _data.queue_) {
        if (q.first) {
            _data.queue_size_ += q.first->size();
        }
    }
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::check_queue_limit(const uint8_t *_data, std::uint32_t _size,
        endpoint_data_type &_endpoint_data) const {

    // No queue limit --> Fine
    if (endpoint_impl<Protocol>::queue_limit_ == QUEUE_SIZE_UNLIMITED) {
        return true;
    }

    // Current queue size is bigger than the maximum queue size
    if (_endpoint_data.queue_size_ >= endpoint_impl<Protocol>::queue_limit_) {
        size_t its_error_queue_size { _endpoint_data.queue_size_ };
        recalculate_queue_size(_endpoint_data);

        VSOMEIP_WARNING << __func__ << ": Detected possible queue size underflow ("
            << std::dec << its_error_queue_size  << "). Recalculating it ("
            << std::dec << _endpoint_data.queue_size_ << ")";
    }

    if (_endpoint_data.queue_size_ + _size > endpoint_impl<Protocol>::queue_limit_
        || _endpoint_data.queue_size_ + _size < _size) { // overflow protection
        service_t its_service(0);
        method_t its_method(0);
        client_t its_client(0);
        session_t its_session(0);
        if (_size >= VSOMEIP_SESSION_POS_MAX) {
            // this will yield wrong IDs for local communication as the commands
            // are prepended to the actual payload
            // it will print:
            // (lowbyte service ID + highbyte methoid)
            // [(Command + lowerbyte sender's client ID).
            //  highbyte sender's client ID + lowbyte command size.
            //  lowbyte methodid + highbyte vsomeip length]
            its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
            its_method  = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);
            its_client  = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
            its_session = bithelper::read_uint16_be(&_data[VSOMEIP_SESSION_POS_MIN]);
        }
        VSOMEIP_ERROR << "sei::send_intern: queue size limit (" << std::dec
                << endpoint_impl<Protocol>::queue_limit_
                << ") reached. Dropping message ("
                << std::hex << std::setfill('0')
                << std::setw(4) << its_client << "): ["
                << std::setw(4) << its_service << "."
                << std::setw(4) << its_method << "."
                << std::setw(4) << its_session << "]"
                << " queue_size: " << std::dec << _endpoint_data.queue_size_
                << " data size: " << _size;
        return false;
    }
    return true;
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::queue_train(
        target_data_iterator_type _it, const std::shared_ptr<train> &_train) {

    bool must_erase(false);

    auto &its_data = _it->second;
    its_data.queue_size_ += _train->buffer_->size();
    its_data.queue_.emplace_back(_train->buffer_, 0);

    if (!its_data.is_sending_) { // no writing in progress
        must_erase = send_queued(_it);
    }

    return must_erase;
}

template<typename Protocol>
bool server_endpoint_impl<Protocol>::flush(endpoint_type _key) {

    bool has_queued(true);
    bool is_current_train(true);

    std::lock_guard<std::mutex> its_lock(mutex_);

    auto it = targets_.find(_key);
    if (it == targets_.end())
        return false;

    auto &its_data = it->second;
    auto its_train(its_data.train_);
    if (!its_data.dispatched_trains_.empty()) {

        auto its_dispatched = its_data.dispatched_trains_.begin();
        if (its_dispatched->first <= its_train->departure_) {

            is_current_train = false;
            if (!its_dispatched->second.empty()) {
                its_train = its_dispatched->second.front();
                its_dispatched->second.pop_front();
                if (its_dispatched->second.empty()) {

                    its_data.dispatched_trains_.erase(its_dispatched);
                }
            }
        }
    }

    if (!its_train->buffer_->empty()) {

        queue_train(it, its_train);

        // Reset current train if necessary
        if (is_current_train) {
            its_train->reset();
        }
    } else {
        has_queued = false;
    }

    if (!is_current_train || !its_data.dispatched_trains_.empty()) {

        auto its_now(std::chrono::steady_clock::now());
        start_dispatch_timer(it, its_now);
    }

    return has_queued;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::connect_cbk(
        boost::system::error_code const &_error) {
    (void)_error;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::send_cbk(const endpoint_type _key,
                                              boost::system::error_code const& _error,
                                              std::size_t _bytes) {
    (void)_bytes;
    // Helper
    auto check_if_all_msgs_for_stopped_service_are_sent = [&]() {
        bool found_service_msg(false);
        service_t its_stopped_service(ANY_SERVICE);
        for (auto stp_hndlr_iter = prepare_stop_handlers_.begin();
                  stp_hndlr_iter != prepare_stop_handlers_.end();) {
            its_stopped_service = stp_hndlr_iter->first;
            if (its_stopped_service == ANY_SERVICE) {
                ++stp_hndlr_iter;
                continue;
            }
            for (const auto& t : targets_) {
                for (const auto& e : t.second.queue_ ) {
                    const service_t its_service = bithelper::read_uint16_be(&(*e.first)[VSOMEIP_SERVICE_POS_MIN]);
                    if (its_service == its_stopped_service) {
                        found_service_msg = true;
                        break;
                    }
                }
                if (found_service_msg) {
                    break;
                }
            }
            if (found_service_msg) {
                ++stp_hndlr_iter;
            } else { // all messages of the to be stopped service have been sent
                auto handler = stp_hndlr_iter->second;
                auto ptr = this->shared_from_this();
                endpoint_impl<Protocol>::io_.post([ptr, handler]() { handler(ptr); });
                stp_hndlr_iter = prepare_stop_handlers_.erase(stp_hndlr_iter);
            }
        }
    };

    auto check_if_all_queues_are_empty = [&](){
        if (prepare_stop_handlers_.size() > 1) {
            // before the endpoint was stopped completely other
            // prepare_stop_handlers have been queued ensure to call them as well
            check_if_all_msgs_for_stopped_service_are_sent();
        }
        if (std::all_of(targets_.begin(), targets_.end(),
                        [&](const typename target_data_type::value_type &_t)
                        { return _t.second.queue_.empty(); })) {
            // all outstanding response have been sent.
            auto found_cbk = prepare_stop_handlers_.find(ANY_SERVICE);
            if (found_cbk != prepare_stop_handlers_.end()) {
                auto handler = found_cbk->second;
                auto ptr = this->shared_from_this();
                endpoint_impl<Protocol>::io_.post([ptr, handler]() { handler(ptr); });
                prepare_stop_handlers_.erase(found_cbk);
            }
        }
    };

    std::lock_guard<std::mutex> its_lock(mutex_);

    auto it = targets_.find(_key);
    if (it == targets_.end())
        return;

    auto& its_data = it->second;

    boost::system::error_code ec;
    its_data.sent_timer_.cancel(ec);

    // Extracts some information for logging puposes.
    //
    // TODO(brunoldsilva): Code like this is used in a lot of places. It might be worth moving this
    // into a proper function.
    auto parse_message_ids = [] (
        const message_buffer_ptr_t& buffer,
        service_t& its_service,
        method_t& its_method,
        client_t& its_client,
        session_t& its_session
    ) {
        if (buffer && buffer->size() > VSOMEIP_SESSION_POS_MAX) {
            its_service = bithelper::read_uint16_be(&(*buffer)[VSOMEIP_SERVICE_POS_MIN]);
            its_method  = bithelper::read_uint16_be(&(*buffer)[VSOMEIP_METHOD_POS_MIN]);
            its_client  = bithelper::read_uint16_be(&(*buffer)[VSOMEIP_CLIENT_POS_MIN]);
            its_session = bithelper::read_uint16_be(&(*buffer)[VSOMEIP_SESSION_POS_MIN]);
        }
    };


    message_buffer_ptr_t its_buffer;
    if (its_data.queue_.size()) {
        its_buffer = its_data.queue_.front().first;
    }

    if (!its_buffer) {
        // Pointer not initialized.
        its_buffer = std::make_shared<message_buffer_t>();
        VSOMEIP_WARNING << __func__ << ": prevented nullptr de-reference by initializing queue buffer";
    }

    service_t its_service(0);
    method_t its_method(0);
    client_t its_client(0);
    session_t its_session(0);

    if (!_error) {
        const std::size_t payload_size = its_buffer->size();
        if (payload_size <= its_data.queue_size_) {
            its_data.queue_size_ -= payload_size;
            its_data.queue_.pop_front();
        } else {
            parse_message_ids(its_buffer, its_service, its_method, its_client, its_session);
            VSOMEIP_WARNING << __func__ << ": prevented queue_size underflow. queue_size: "
                << its_data.queue_size_ << " payload_size: " << payload_size << " payload: ("
                << std::hex << std::setw(4) << std::setfill('0') << its_client <<"): ["
                << std::hex << std::setw(4) << std::setfill('0') << its_service << "."
                << std::hex << std::setw(4) << std::setfill('0') << its_method << "."
                << std::hex << std::setw(4) << std::setfill('0') << its_session << "]";
            its_data.queue_.pop_front();
            recalculate_queue_size(its_data);
        }

        update_last_departure(its_data);

        if (!prepare_stop_handlers_.empty() && !endpoint_impl<Protocol>::sending_blocked_) {
            // only one service instance is stopped
            check_if_all_msgs_for_stopped_service_are_sent();
        }

        if (!its_data.queue_.empty()) {
            (void)send_queued(it);
        } else {
            if (!prepare_stop_handlers_.empty() && endpoint_impl<Protocol>::sending_blocked_) {
                // endpoint is shutting down completely
                cancel_dispatch_timer(it);
                targets_.erase(it);
                check_if_all_queues_are_empty();
            } else
                its_data.is_sending_ = false;
        }
    } else {
        // error: sending of outstanding responses isn't started again
        // delete remaining outstanding responses
        parse_message_ids(its_buffer, its_service, its_method, its_client, its_session);
        VSOMEIP_WARNING << "sei::send_cbk received error: " << _error.message()
                << " (" << std::dec << _error.value() << ") "
                << get_remote_information(it) << " "
                << std::dec << its_data.queue_.size() << " "
                << its_data.queue_size_ << " ("
                << std::hex << std::setfill('0')
                << std::setw(4) << its_client << "): ["
                << std::setw(4) << its_service << "."
                << std::setw(4) << its_method << "."
                << std::setw(4) << its_session << "]";
        cancel_dispatch_timer(it);
        targets_.erase(it);
        if (!prepare_stop_handlers_.empty()) {
            if (endpoint_impl<Protocol>::sending_blocked_) {
                // endpoint is shutting down completely, ensure to call
                // prepare_stop_handlers even in error cases
                check_if_all_queues_are_empty();
            } else {
                // only one service instance is stopped
                check_if_all_msgs_for_stopped_service_are_sent();
            }
        }
    }
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::flush_cbk(
        endpoint_type _key,
        const boost::system::error_code &_error_code) {

    if (!_error_code) {

        (void) flush(_key);
    }
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::remove_stop_handler(service_t _service) {
    std::stringstream its_services_log;
    its_services_log << __func__ << ": ";

    std::lock_guard<std::mutex> its_lock{mutex_};
    for (const auto &its_service : prepare_stop_handlers_)
        its_services_log << std::hex << std::setw(4) << std::setfill('0') << its_service.first << ' ';

    VSOMEIP_INFO << its_services_log.str();
    prepare_stop_handlers_.erase(_service);
}

template<typename Protocol>
size_t server_endpoint_impl<Protocol>::get_queue_size() const {
    size_t its_queue_size(0);
    {
        std::lock_guard<std::mutex> its_lock(mutex_);
        for (const auto &t : targets_) {
            its_queue_size += t.second.queue_size_;
        }
    }
    return its_queue_size;
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::start_dispatch_timer(
        target_data_iterator_type _it,
        const std::chrono::steady_clock::time_point &_now) {

    auto &its_data = _it->second;
    std::shared_ptr<train> its_train(its_data.train_);

    if (!its_data.dispatched_trains_.empty()) {

        auto its_dispatched = its_data.dispatched_trains_.begin();
        if (its_dispatched->first < its_train->departure_) {

            its_train = its_dispatched->second.front();
        }
    }

    std::chrono::nanoseconds its_offset;
    if (its_train->departure_ > _now) {

        its_offset = std::chrono::duration_cast<std::chrono::nanoseconds>(
                its_train->departure_ - _now);
    } else { // already departure time

        its_offset = std::chrono::nanoseconds::zero();
    }

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    its_data.dispatch_timer_->expires_from_now(its_offset);
#else
    its_data.dispatch_timer_->expires_from_now(
            std::chrono::duration_cast<
                std::chrono::steady_clock::duration>(its_offset));
#endif
    its_data.dispatch_timer_->async_wait(
            std::bind(&server_endpoint_impl<Protocol>::flush_cbk,
                      this->shared_from_this(), _it->first, std::placeholders::_1));
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::cancel_dispatch_timer(
        target_data_iterator_type _it) {

    boost::system::error_code ec;
    _it->second.dispatch_timer_->cancel(ec);
}

template<typename Protocol>
void server_endpoint_impl<Protocol>::update_last_departure(
        endpoint_data_type &_data) {

    _data.last_departure_ = std::chrono::steady_clock::now();
    _data.has_last_departure_ = true;
}

// Instantiate template
#if defined(__linux__) || defined(__QNX__)
template class server_endpoint_impl<boost::asio::local::stream_protocol>;
#endif

template class server_endpoint_impl<boost::asio::ip::tcp>;
template class server_endpoint_impl<boost::asio::ip::udp>;

}  // namespace vsomeip_v3
