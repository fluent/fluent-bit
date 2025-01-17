// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/constants.hpp>

#include <chrono>
#include <iomanip>
#include <forward_list>
#include <random>
#include <thread>

#include <vsomeip/internal/logger.hpp>

#include "../include/constants.hpp"
#include "../include/defines.hpp"
#include "../include/deserializer.hpp"
#include "../include/enumeration_types.hpp"
#include "../include/eventgroupentry_impl.hpp"
#include "../include/ipv4_option_impl.hpp"
#include "../include/ipv6_option_impl.hpp"
#include "../include/selective_option_impl.hpp"
#include "../include/message_impl.hpp"
#include "../include/remote_subscription_ack.hpp"
#include "../include/request.hpp"
#include "../include/runtime.hpp"
#include "../include/service_discovery_host.hpp"
#include "../include/service_discovery_impl.hpp"
#include "../include/serviceentry_impl.hpp"
#include "../include/subscription.hpp"
#include "../../configuration/include/configuration.hpp"
#include "../../endpoints/include/endpoint.hpp"
#include "../../endpoints/include/client_endpoint.hpp"
#include "../../endpoints/include/endpoint_definition.hpp"
#include "../../endpoints/include/tcp_server_endpoint_impl.hpp"
#include "../../endpoints/include/udp_server_endpoint_impl.hpp"
#include "../../message/include/serializer.hpp"
#include "../../plugin/include/plugin_manager_impl.hpp"
#include "../../routing/include/event.hpp"
#include "../../routing/include/eventgroupinfo.hpp"
#include "../../routing/include/serviceinfo.hpp"
#include "../../utility/include/bithelper.hpp"

namespace vsomeip_v3 {
namespace sd {

service_discovery_impl::service_discovery_impl(
        service_discovery_host *_host,
        const std::shared_ptr<configuration>& _configuration)
    : io_(_host->get_io()),
      host_(_host),
      configuration_(_configuration),
      port_(VSOMEIP_SD_DEFAULT_PORT),
      reliable_(false),
      serializer_(std::make_shared<serializer>(
                      configuration_->get_buffer_shrink_threshold())),
      deserializer_(std::make_shared<deserializer>(
                      configuration_->get_buffer_shrink_threshold())),
      ttl_timer_(_host->get_io()),
      ttl_timer_runtime_(VSOMEIP_SD_DEFAULT_CYCLIC_OFFER_DELAY / 2),
      ttl_(VSOMEIP_SD_DEFAULT_TTL),
      subscription_expiration_timer_(_host->get_io()),
      max_message_size_(VSOMEIP_MAX_UDP_SD_PAYLOAD),
      initial_delay_(0),
      offer_debounce_time_(VSOMEIP_SD_DEFAULT_OFFER_DEBOUNCE_TIME),
      repetitions_base_delay_(VSOMEIP_SD_DEFAULT_REPETITIONS_BASE_DELAY),
      repetitions_max_(VSOMEIP_SD_DEFAULT_REPETITIONS_MAX),
      cyclic_offer_delay_(VSOMEIP_SD_DEFAULT_CYCLIC_OFFER_DELAY),
      offer_debounce_timer_(_host->get_io()),
      find_debounce_time_(VSOMEIP_SD_DEFAULT_FIND_DEBOUNCE_TIME),
      find_debounce_timer_(_host->get_io()),
      main_phase_timer_(_host->get_io()),
      is_suspended_(false),
      is_diagnosis_(false),
      last_msg_received_timer_(_host->get_io()),
      last_msg_received_timer_timeout_(VSOMEIP_SD_DEFAULT_CYCLIC_OFFER_DELAY +
                                           (VSOMEIP_SD_DEFAULT_CYCLIC_OFFER_DELAY / 10)) {

    next_subscription_expiration_ = std::chrono::steady_clock::now() + std::chrono::hours(24);
}

service_discovery_impl::~service_discovery_impl() {
}

boost::asio::io_context &service_discovery_impl::get_io() {
    return io_;
}

void
service_discovery_impl::init() {
    runtime_ = std::dynamic_pointer_cast<sd::runtime>(
            plugin_manager::get()->get_plugin(
                    plugin_type_e::SD_RUNTIME_PLUGIN, VSOMEIP_SD_LIBRARY));

    unicast_ = configuration_->get_unicast_address();
    sd_multicast_ = configuration_->get_sd_multicast();
    boost::system::error_code ec;
    sd_multicast_address_ = boost::asio::ip::address::from_string(sd_multicast_, ec);

    port_ = configuration_->get_sd_port();
    reliable_ = (configuration_->get_sd_protocol() == "tcp");
    max_message_size_ = (reliable_ ? VSOMEIP_MAX_TCP_SD_PAYLOAD :
            VSOMEIP_MAX_UDP_SD_PAYLOAD);

    ttl_ = configuration_->get_sd_ttl();

    // generate random initial delay based on initial delay min and max
    std::uint32_t initial_delay_min =
            configuration_->get_sd_initial_delay_min();
    std::uint32_t initial_delay_max =
            configuration_->get_sd_initial_delay_max();
    if (initial_delay_min > initial_delay_max) {
        const std::uint32_t tmp(initial_delay_min);
        initial_delay_min = initial_delay_max;
        initial_delay_max = tmp;
    }

    try {
        std::random_device r;
        std::mt19937 e(r());
        std::uniform_int_distribution<std::uint32_t> distribution(
                initial_delay_min, initial_delay_max);
        initial_delay_ = std::chrono::milliseconds(distribution(e));
    } catch (const std::exception& e) {
        VSOMEIP_ERROR << "Failed to generate random initial delay: " << e.what();

        // Fallback to the Mersenne Twister engine
        const auto seed = static_cast<std::mt19937::result_type>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch())
                .count());

        std::mt19937 mtwister{seed};

        // Interpolate between initial_delay bounds
        initial_delay_ = std::chrono::milliseconds(
            initial_delay_min +
            (static_cast<std::int64_t>(mtwister()) *
             static_cast<std::int64_t>(initial_delay_max - initial_delay_min) /
             static_cast<std::int64_t>(std::mt19937::max() -
                                       std::mt19937::min())));
    }


    repetitions_base_delay_ = std::chrono::milliseconds(
            configuration_->get_sd_repetitions_base_delay());
    repetitions_max_ = configuration_->get_sd_repetitions_max();
    cyclic_offer_delay_ = std::chrono::milliseconds(
            configuration_->get_sd_cyclic_offer_delay());
    offer_debounce_time_ = std::chrono::milliseconds(
            configuration_->get_sd_offer_debounce_time());
    ttl_timer_runtime_ = cyclic_offer_delay_ / 2;
    find_debounce_time_ = std::chrono::milliseconds(
            configuration_->get_sd_find_debounce_time());

    ttl_factor_offers_ = configuration_->get_ttl_factor_offers();
    ttl_factor_subscriptions_ = configuration_->get_ttl_factor_subscribes();
    last_msg_received_timer_timeout_ = cyclic_offer_delay_
            + (cyclic_offer_delay_ / 10);
}

void
service_discovery_impl::start() {
    if (!endpoint_) {
        endpoint_ = host_->create_service_discovery_endpoint(
                sd_multicast_, port_, reliable_);
        if (!endpoint_) {
            VSOMEIP_ERROR << "Couldn't start service discovery";
            return;
        }
    }
    {
        std::lock_guard<std::mutex> its_lock(sessions_received_mutex_);
        sessions_received_.clear();
    }
    {
        std::lock_guard<std::mutex> its_lock(serialize_mutex_);
        sessions_sent_.clear();
    }

    if (is_suspended_) {
        // make sure to sent out FindService messages after resume
        std::lock_guard<std::mutex> its_lock(requested_mutex_);
        for (const auto &s : requested_) {
            for (const auto &i : s.second) {
                i.second->set_sent_counter(0);
            }
        }

        // rejoin multicast group
        if (endpoint_ && !reliable_) {
            auto its_server_endpoint
                = std::dynamic_pointer_cast<udp_server_endpoint_impl>(endpoint_);
            if (its_server_endpoint)
                its_server_endpoint->join(sd_multicast_);
        }
    }
    is_suspended_ = false;
    start_main_phase_timer();
    start_offer_debounce_timer(true);
    start_find_debounce_timer(true);
    start_ttl_timer();
}

void
service_discovery_impl::stop() {
    is_suspended_ = true;
    stop_ttl_timer();
    stop_last_msg_received_timer();
    stop_main_phase_timer();
}

void
service_discovery_impl::request_service(
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor,
        ttl_t _ttl) {
    std::lock_guard<std::mutex> its_lock(requested_mutex_);
    auto find_service = requested_.find(_service);
    if (find_service != requested_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance == find_service->second.end()) {
            find_service->second[_instance]
                = std::make_shared<request>(_major, _minor, _ttl);
        }
    } else {
        requested_[_service][_instance]
            = std::make_shared<request>(_major, _minor, _ttl);
    }
}

void
service_discovery_impl::release_service(
        service_t _service, instance_t _instance) {
    std::lock_guard<std::mutex> its_lock(requested_mutex_);
    auto find_service = requested_.find(_service);
    if (find_service != requested_.end()) {
        find_service->second.erase(_instance);
    }
}

void
service_discovery_impl::update_request(service_t _service, instance_t _instance) {
    std::lock_guard<std::mutex> its_lock(requested_mutex_);
    auto find_service = requested_.find(_service);
    if (find_service != requested_.end()) {
        auto find_instance = find_service->second.find(_instance);
        if (find_instance != find_service->second.end()) {
            find_instance->second->set_sent_counter(
                    std::uint8_t(repetitions_max_ + 1));
        }
    }
}

std::recursive_mutex&
service_discovery_impl::get_subscribed_mutex() {
    return subscribed_mutex_;
}

void
service_discovery_impl::subscribe(
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, major_version_t _major,
        ttl_t _ttl, client_t _client,
        const std::shared_ptr<eventgroupinfo> &_info) {

    if (is_suspended_) {
        VSOMEIP_WARNING << "service_discovery::" << __func__
                << ": Ignoring subscription as we are suspended.";
        return;
    }

#ifdef VSOMEIP_ENABLE_COMPAT
    bool is_selective(_info ? _info->is_selective() : false);
#endif // VSOMEIP_ENABLE_COMPAT

    std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
    auto found_service = subscribed_.find(_service);
    if (found_service != subscribed_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                auto its_subscription = found_eventgroup->second;
#ifdef VSOMEIP_ENABLE_COMPAT
                if (!its_subscription->is_selective() && is_selective) {
                    its_subscription->set_selective(true);
                    its_subscription->remove_client(VSOMEIP_ROUTING_CLIENT);
                    for (const auto &e : _info->get_events()) {
                        for (const auto &c : e->get_subscribers(_eventgroup)) {
                            its_subscription->add_client(c);
                        }
                    }
                }
#endif // VSOMEIP_ENABLE_COMPAT
                if (its_subscription->get_major() != _major) {
                    VSOMEIP_ERROR
                            << "Subscriptions to different versions of the same "
                                    "service instance are not supported!";
                } else if (its_subscription->is_selective()) {
                    if (its_subscription->add_client(_client)) {
                        its_subscription->set_state(_client,
                                subscription_state_e::ST_NOT_ACKNOWLEDGED);
                        send_subscription(its_subscription,
                                _service, _instance, _eventgroup,
                                _client);
                    }
                }
                return;
            }
        }
    }

    std::shared_ptr<endpoint> its_reliable, its_unreliable;
        get_subscription_endpoints(_service, _instance,
                its_reliable, its_unreliable);

    // New subscription
    std::shared_ptr<subscription> its_subscription
        = create_subscription(
                _major, _ttl, its_reliable, its_unreliable, _info);

    if (!its_subscription) {
        VSOMEIP_ERROR << __func__
                << ": creating subscription failed!";
        return;
    }

    subscribed_[_service][_instance][_eventgroup] = its_subscription;

    its_subscription->add_client(_client);
    its_subscription->set_state(_client,
            subscription_state_e::ST_NOT_ACKNOWLEDGED);

    send_subscription(its_subscription,
            _service, _instance, _eventgroup,
            _client);
}

void
service_discovery_impl::send_subscription(
        const std::shared_ptr<subscription> &_subscription,
        const service_t _service, const instance_t _instance,
        const eventgroup_t _eventgroup,
        const client_t _client) {
    (void)_client;

    auto its_reliable = _subscription->get_endpoint(true);
    auto its_unreliable = _subscription->get_endpoint(false);

    boost::asio::ip::address its_address;
    get_subscription_address(its_reliable, its_unreliable, its_address);
    if (!its_address.is_unspecified()) {
        entry_data_t its_data;
        const reliability_type_e its_reliability_type =
                get_eventgroup_reliability(_service, _instance, _eventgroup, _subscription);
        if (its_reliability_type == reliability_type_e::RT_UNRELIABLE && its_unreliable) {
            if (its_unreliable->is_established()) {
                its_data = create_eventgroup_entry(_service, _instance,
                        _eventgroup, _subscription, its_reliability_type);
            } else {
                _subscription->set_udp_connection_established(false);
            }
        } else if (its_reliability_type == reliability_type_e::RT_RELIABLE && its_reliable) {
            if (its_reliable->is_established()) {
                its_data = create_eventgroup_entry(_service, _instance,
                        _eventgroup, _subscription, its_reliability_type);
            } else {
                _subscription->set_tcp_connection_established(false);
            }
        } else if (its_reliability_type == reliability_type_e::RT_BOTH &&
                its_reliable && its_unreliable) {
            if (its_reliable->is_established() && its_unreliable->is_established()) {
                its_data = create_eventgroup_entry(_service, _instance,
                        _eventgroup, _subscription, its_reliability_type);
            } else {
                if (!its_reliable->is_established()) {
                    _subscription->set_tcp_connection_established(false);
                }
                if (!its_unreliable->is_established()) {
                    _subscription->set_udp_connection_established(false);
                }
            }
        } else if (its_reliability_type == reliability_type_e::RT_UNKNOWN) {
            VSOMEIP_WARNING << "sd::" << __func__ << ": couldn't determine reliability type for subscription to ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << "."
                    << std::setw(4) << _eventgroup << "] ";
        }

        if (its_data.entry_) {
            // TODO: Implement a simple path, that sends a single message
            auto its_current_message = std::make_shared<message_impl>();
            std::vector<std::shared_ptr<message_impl> > its_messages;
            its_messages.push_back(its_current_message);

            add_entry_data(its_messages, its_data);

            serialize_and_send(its_messages, its_address);
        }
    }
}

void
service_discovery_impl::get_subscription_endpoints(
        service_t _service, instance_t _instance,
        std::shared_ptr<endpoint> &_reliable,
        std::shared_ptr<endpoint> &_unreliable) const {
    _unreliable = host_->find_or_create_remote_client(
            _service, _instance, false);
    _reliable = host_->find_or_create_remote_client(
            _service, _instance, true);
}

void
service_discovery_impl::get_subscription_address(
        const std::shared_ptr<endpoint> &_reliable,
        const std::shared_ptr<endpoint> &_unreliable,
        boost::asio::ip::address &_address) const {
    if (_reliable) {
        auto its_client_endpoint
            = std::dynamic_pointer_cast<client_endpoint>(_reliable);
        if (its_client_endpoint) {
            its_client_endpoint->get_remote_address(_address);
            return;
        }
    }
    if (_unreliable) {
        auto its_client_endpoint
            = std::dynamic_pointer_cast<client_endpoint>(_unreliable);
        if (its_client_endpoint) {
            its_client_endpoint->get_remote_address(_address);
        }
    }
}

void
service_discovery_impl::unsubscribe(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup, client_t _client) {
    std::shared_ptr < runtime > its_runtime = runtime_.lock();
    if (!its_runtime) {
        return;
    }

    auto its_current_message = std::make_shared<message_impl>();

    boost::asio::ip::address its_address;
    {
        std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
        auto found_service = subscribed_.find(_service);
        if (found_service != subscribed_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                auto found_eventgroup = found_instance->second.find(_eventgroup);
                if (found_eventgroup != found_instance->second.end()) {
                    auto its_subscription = found_eventgroup->second;
                    if (its_subscription->remove_client(_client)) {
                        auto its_reliable = its_subscription->get_endpoint(true);
                        auto its_unreliable = its_subscription->get_endpoint(false);
                        get_subscription_address(
                                its_reliable, its_unreliable, its_address);
                        if (!its_subscription->has_client()) {
                            its_subscription->set_ttl(0);
                        } else if (its_subscription->is_selective()) {
                            // create a dummy subscription object to unsubscribe
                            // the single client.
                            auto its_major = its_subscription->get_major();

                            its_subscription = std::make_shared<subscription>();
                            its_subscription->set_major(its_major);
                            its_subscription->set_ttl(0);
                            its_subscription->set_selective(true);
                            its_subscription->set_endpoint(its_reliable, true);
                            its_subscription->set_endpoint(its_unreliable, false);
                        }
                    }

                    // For selective subscriptions, the client must be added again
                    // to generate the selective option
                    if (its_subscription->is_selective())
                        its_subscription->add_client(_client);

                    const reliability_type_e its_reliability_type =
                            get_eventgroup_reliability(_service, _instance, _eventgroup, its_subscription);
                    auto its_data = create_eventgroup_entry(_service, _instance,
                        _eventgroup, its_subscription, its_reliability_type);
                    if (its_data.entry_)
                        its_current_message->add_entry_data(its_data.entry_, its_data.options_);

                    // Remove it again before updating (only impacts last unsubscribe)
                    if (its_subscription->is_selective())
                        (void)its_subscription->remove_client(_client);

                    // Ensure to update the "real" subscription
                    its_subscription = found_eventgroup->second;

                    // Finally update the subscriptions
                    if (!its_subscription->has_client()) {
                        found_instance->second.erase(found_eventgroup);
                        if (found_instance->second.size() == 0) {
                            found_service->second.erase(found_instance);
                        }
                    }
                }
            }
        }
    }

    std::vector<std::shared_ptr<message_impl> > its_messages;
    its_messages.push_back(its_current_message);

    serialize_and_send(its_messages, its_address);
}

void
service_discovery_impl::unsubscribe_all(
        service_t _service, instance_t _instance) {

    auto its_current_message = std::make_shared<message_impl>();
    boost::asio::ip::address its_address;

    {
        std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
        auto found_service = subscribed_.find(_service);
        if (found_service != subscribed_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                for (auto &its_eventgroup : found_instance->second) {
                    auto its_subscription = its_eventgroup.second;
                    its_subscription->set_ttl(0);

                    const reliability_type_e its_reliability =
                            get_eventgroup_reliability(_service, _instance,
                                its_eventgroup.first, its_subscription);

                    auto its_data = create_eventgroup_entry(_service, _instance,
                            its_eventgroup.first, its_subscription, its_reliability);
                    auto its_reliable = its_subscription->get_endpoint(true);
                    auto its_unreliable = its_subscription->get_endpoint(false);
                    get_subscription_address(
                            its_reliable, its_unreliable, its_address);
                    if (its_data.entry_) {
                        its_current_message->add_entry_data(its_data.entry_, its_data.options_);
                    }
                }
                found_instance->second.clear();
            }
        }
    }

    std::vector<std::shared_ptr<message_impl> > its_messages;
    its_messages.push_back(its_current_message);

    serialize_and_send(its_messages, its_address);
}


void
service_discovery_impl::unsubscribe_all_on_suspend() {

    std::map<boost::asio::ip::address,
            std::vector<std::shared_ptr<message_impl> > > its_stopsubscribes;

    {
        std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
        for (auto its_service : subscribed_) {
            for (auto its_instance : its_service.second) {
                for (auto &its_eventgroup : its_instance.second) {
                    boost::asio::ip::address its_address;
                    auto its_current_message = std::make_shared<message_impl>();
                    auto its_subscription = its_eventgroup.second;
                    its_subscription->set_ttl(0);
                    const reliability_type_e its_reliability =
                          get_eventgroup_reliability(its_service.first, its_instance.first,
                                  its_eventgroup.first, its_subscription);
                    auto its_data = create_eventgroup_entry(its_service.first, its_instance.first,
                            its_eventgroup.first, its_subscription, its_reliability);
                    auto its_reliable = its_subscription->get_endpoint(true);
                    auto its_unreliable = its_subscription->get_endpoint(false);
                    get_subscription_address(
                            its_reliable, its_unreliable, its_address);
                    if (its_data.entry_
                            && its_current_message->add_entry_data(its_data.entry_, its_data.options_)) {
                        its_stopsubscribes[its_address].push_back(its_current_message);
                    } else {
                        VSOMEIP_WARNING << __func__ << ": Failed to create StopSubscribe entry for: "
                            << std::hex << std::setfill('0')
                            << std::setw(4) << its_service.first << "."
                            << std::setw(4) << its_instance.first << "."
                            << std::setw(4) << its_eventgroup.first
                            << " address: " << its_address.to_string();
                    }
                }
                its_instance.second.clear();
            }
            its_service.second.clear();
        }
        subscribed_.clear();
    }

    for (auto its_address : its_stopsubscribes) {
        if (!serialize_and_send(its_address.second, its_address.first)) {
            VSOMEIP_WARNING << __func__ << ": Failed to send StopSubscribe to address: "
                    << its_address.first.to_string();
        }
    }
}

void
service_discovery_impl::remove_subscriptions(
        service_t _service, instance_t _instance) {

    std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
    auto found_service = subscribed_.find(_service);
    if (found_service != subscribed_.end()) {
        found_service->second.erase(_instance);
        if (found_service->second.empty()) {
            subscribed_.erase(found_service);
        }
    }
}

std::pair<session_t, bool>
service_discovery_impl::get_session(
        const boost::asio::ip::address &_address) {
    std::pair<session_t, bool> its_session;
    auto found_session = sessions_sent_.find(_address);
    if (found_session == sessions_sent_.end()) {
        its_session = sessions_sent_[_address] = { 1, true };
    } else {
        its_session = found_session->second;
    }
    return its_session;
}

void
service_discovery_impl::increment_session(
        const boost::asio::ip::address &_address) {
    auto found_session = sessions_sent_.find(_address);
    if (found_session != sessions_sent_.end()) {
        found_session->second.first++;
        if (found_session->second.first == 0) {
            found_session->second = { 1, false };
        }
    }
}

bool
service_discovery_impl::is_reboot(
        const boost::asio::ip::address &_sender,
        bool _is_multicast,
        bool _reboot_flag, session_t _session) {
    bool result(false);

    auto its_received = sessions_received_.find(_sender);

    // Initialize both sessions with 0. Thus, the session identifier
    // for the session not being received from the network is stored
    // as 0 and will never trigger the reboot detection.
    session_t its_multicast_session(0), its_unicast_session(0);

    // Initialize both flags with true. Thus, the flag not being
    // received from the network will never trigger the reboot detection.
    bool its_multicast_reboot_flag(true), its_unicast_reboot_flag(true);

    if (_is_multicast) {
        its_multicast_session = _session;
        its_multicast_reboot_flag = _reboot_flag;
    } else {
        its_unicast_session = _session;
        its_unicast_reboot_flag = _reboot_flag;
    }

    if (its_received == sessions_received_.end()) {
        sessions_received_[_sender]
            = std::make_tuple(its_multicast_session, its_unicast_session,
                    its_multicast_reboot_flag, its_unicast_reboot_flag);
    } else {
        // Reboot detection: Either the flag has changed from false to true,
        // or the session identifier overrun while the flag is true.
        if (_reboot_flag
            && ((_is_multicast && !std::get<2>(its_received->second))
                || (!_is_multicast && !std::get<3>(its_received->second)))) {
            result = true;
        } else {
            session_t its_old_session;
            bool its_old_reboot_flag;

            if (_is_multicast) {
                its_old_session = std::get<0>(its_received->second);
                its_old_reboot_flag = std::get<2>(its_received->second);
            } else {
                its_old_session = std::get<1>(its_received->second);
                its_old_reboot_flag = std::get<3>(its_received->second);
            }

            if (its_old_reboot_flag && _reboot_flag
                    && its_old_session >= _session) {
                result = true;
            }
        }

        if (result == false) {
            // no reboot -> update session/flag
            if (_is_multicast) {
                std::get<0>(its_received->second) = its_multicast_session;
                std::get<2>(its_received->second) = its_multicast_reboot_flag;
            } else {
                std::get<1>(its_received->second) = its_unicast_session;
                std::get<3>(its_received->second) = its_unicast_reboot_flag;
            }
        } else {
            // reboot -> reset the sender data
            sessions_received_.erase(_sender);
        }
    }

    return result;
}

bool
service_discovery_impl::check_session_id_sequence(const boost::asio::ip::address &_sender,
                const bool _is_multicast, const session_t &_session,
                session_t &_missing_session) {

    using address_pair_t = std::pair<boost::asio::ip::address, bool>;
    static std::map<address_pair_t, session_t> session_peer;
    address_pair_t peer_to_peer(_sender, _is_multicast);
    std::map<address_pair_t, session_t>::iterator it = session_peer.find(peer_to_peer);
    if (it != session_peer.end()) {
        if ((_session > it->second) && (_session != (it->second+1))) {
            _missing_session = static_cast<session_t>(it->second+1);
            session_peer[peer_to_peer] = _session;
            return false;
        }
    }

    session_peer[peer_to_peer] = _session;
    return true;
}

void
service_discovery_impl::insert_find_entries(
        std::vector<std::shared_ptr<message_impl> > &_messages,
        const requests_t &_requests) {

    entry_data_t its_data;
    its_data.entry_ = its_data.other_ = nullptr;

    for (const auto& its_service : _requests) {
        for (const auto& its_instance : its_service.second) {
            std::lock_guard<std::mutex> its_lock(requested_mutex_);
            auto its_request = its_instance.second;

            // check if release_service was called / offer was received
            auto the_service = requested_.find(its_service.first);
            if ( the_service != requested_.end() ) {
                auto the_instance = the_service->second.find(its_instance.first);
                if(the_instance != the_service->second.end() ) {
                    uint8_t its_sent_counter = its_request->get_sent_counter();
                    if (its_sent_counter != repetitions_max_ + 1) {
                        auto its_entry = std::make_shared<serviceentry_impl>();
                        if (its_entry) {
                            its_entry->set_type(entry_type_e::FIND_SERVICE);
                            its_entry->set_service(its_service.first);
                            its_entry->set_instance(its_instance.first);
                            its_entry->set_major_version(its_request->get_major());
                            its_entry->set_minor_version(its_request->get_minor());
                            its_entry->set_ttl(its_request->get_ttl());
                            its_sent_counter++;

                            its_request->set_sent_counter(its_sent_counter);

                            its_data.entry_ = its_entry;
                            add_entry_data(_messages, its_data);
                        } else {
                            VSOMEIP_ERROR << "Failed to create service entry!";
                        }
                    }
                }
            }
        }
    }
}

void
service_discovery_impl::insert_offer_entries(
        std::vector<std::shared_ptr<message_impl> > &_messages,
        const services_t &_services, bool _ignore_phase) {
    for (const auto& its_service : _services) {
        for (const auto& its_instance : its_service.second) {
            if ((!is_suspended_)
                    && ((!is_diagnosis_)
                    || (is_diagnosis_
                            && !configuration_->is_someip(its_service.first,
                                    its_instance.first)))) {
                // Only insert services with configured endpoint(s)
                if ((_ignore_phase || its_instance.second->is_in_mainphase())
                        && (its_instance.second->get_endpoint(false)
                                || its_instance.second->get_endpoint(true))) {
                    insert_offer_service(_messages, its_instance.second);
                }
            }
        }
    }
}

entry_data_t
service_discovery_impl::create_eventgroup_entry(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        const std::shared_ptr<subscription> &_subscription,
        reliability_type_e _reliability_type) {

    entry_data_t its_data;
    its_data.entry_ = nullptr;
    its_data.other_ = nullptr;

    std::shared_ptr<endpoint> its_reliable_endpoint(_subscription->get_endpoint(true));
    std::shared_ptr<endpoint> its_unreliable_endpoint(_subscription->get_endpoint(false));

    bool insert_reliable(false);
    bool insert_unreliable(false);
    switch (_reliability_type) {
        case reliability_type_e::RT_RELIABLE:
            if (its_reliable_endpoint) {
                insert_reliable = true;
            } else {
                VSOMEIP_WARNING << __func__ << ": Cannot create subscription as "
                        "reliable endpoint is zero: ["
                        << std::hex << std::setfill('0')
                        << std::setw(4) << _service << "."
                        << std::setw(4) << _instance << "."
                        << std::setw(4) << _eventgroup << "]";
            }
            break;
        case reliability_type_e::RT_UNRELIABLE:
            if (its_unreliable_endpoint) {
                insert_unreliable = true;
            } else {
                VSOMEIP_WARNING << __func__ << ": Cannot create subscription as "
                        "unreliable endpoint is zero: ["
                        << std::hex << std::setfill('0')
                        << std::setw(4) << _service << "."
                        << std::setw(4) << _instance << "."
                        << std::setw(4) << _eventgroup << "]";
            }
            break;
        case reliability_type_e::RT_BOTH:
            if (its_reliable_endpoint && its_unreliable_endpoint) {
                insert_reliable = true;
                insert_unreliable = true;
            } else {
                VSOMEIP_WARNING << __func__ << ": Cannot create subscription as "
                        "endpoint is zero: ["
                        << std::hex << std::setfill('0')
                        << std::setw(4) << _service << "."
                        << std::setw(4) << _instance << "."
                        << std::setw(4) << _eventgroup << "]"
                        << " reliable: " << !!its_reliable_endpoint
                        << " unreliable: " << !!its_unreliable_endpoint;
            }
            break;
        default:
            break;
    }

    if (!insert_reliable && !insert_unreliable
            && _reliability_type != reliability_type_e::RT_UNKNOWN) {
        VSOMEIP_WARNING << __func__ << ": Didn't insert subscription as "
                "subscription doesn't match reliability type: ["
                << std::hex << std::setfill('0')
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _eventgroup << "] "
                << static_cast<uint16_t>(_reliability_type);
        return its_data;
    }
    std::shared_ptr<eventgroupentry_impl> its_entry, its_other;
    if (insert_reliable && its_reliable_endpoint) {
        const std::uint16_t its_port = its_reliable_endpoint->get_local_port();
        if (its_port) {
            its_entry = std::make_shared<eventgroupentry_impl>();
            if (!its_entry) {
                VSOMEIP_ERROR << __func__
                        << ": Could not create eventgroup entry.";
                return its_data;
            }

            its_entry->set_type(entry_type_e::SUBSCRIBE_EVENTGROUP);
            its_entry->set_service(_service);
            its_entry->set_instance(_instance);
            its_entry->set_eventgroup(_eventgroup);
            its_entry->set_counter(0);
            its_entry->set_major_version(_subscription->get_major());
            its_entry->set_ttl(_subscription->get_ttl());
            its_data.entry_ = its_entry;

            for (const auto its_client : _subscription->get_clients()) {
                if (_subscription->get_state(its_client)
                        == subscription_state_e::ST_RESUBSCRIBING_NOT_ACKNOWLEDGED) {
                    its_other = std::make_shared<eventgroupentry_impl>();
                    its_other->set_type(entry_type_e::SUBSCRIBE_EVENTGROUP);
                    its_other->set_service(_service);
                    its_other->set_instance(_instance);
                    its_other->set_eventgroup(_eventgroup);
                    its_other->set_counter(0);
                    its_other->set_major_version(_subscription->get_major());
                    its_other->set_ttl(0);
                    its_data.other_ = its_other;
                    break;
                }
            }

            auto its_option = create_ip_option(unicast_, its_port, true);
            its_data.options_.push_back(its_option);
        } else {
            VSOMEIP_WARNING << __func__ << ": Cannot create subscription as "
                    "local reliable port is zero: ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << "."
                    << std::setw(4) << _eventgroup << "]";
            its_data.entry_ = nullptr;
            its_data.other_ = nullptr;
            return its_data;
        }
    }

    if (insert_unreliable && its_unreliable_endpoint) {
        const std::uint16_t its_port = its_unreliable_endpoint->get_local_port();
        if (its_port) {
            if (!its_entry) {
                its_entry = std::make_shared<eventgroupentry_impl>();
                if (!its_entry) {
                    VSOMEIP_ERROR << __func__
                            << ": Could not create eventgroup entry.";
                    return its_data;
                }

                its_entry->set_type(entry_type_e::SUBSCRIBE_EVENTGROUP);
                its_entry->set_service(_service);
                its_entry->set_instance(_instance);
                its_entry->set_eventgroup(_eventgroup);
                its_entry->set_counter(0);
                its_entry->set_major_version(_subscription->get_major());
                its_entry->set_ttl(_subscription->get_ttl());
                its_data.entry_ = its_entry;
            }

            for (const auto its_client : _subscription->get_clients()) {
                if (_subscription->get_state(its_client)
                        == subscription_state_e::ST_RESUBSCRIBING_NOT_ACKNOWLEDGED) {
                    if (!its_other) {
                        its_other = std::make_shared<eventgroupentry_impl>();
                        its_other->set_type(entry_type_e::SUBSCRIBE_EVENTGROUP);
                        its_other->set_service(_service);
                        its_other->set_instance(_instance);
                        its_other->set_eventgroup(_eventgroup);
                        its_other->set_counter(0);
                        its_other->set_major_version(_subscription->get_major());
                        its_other->set_ttl(0);
                        its_data.other_ = its_other;
                        break;
                    }
                }
            }

            auto its_option = create_ip_option(unicast_, its_port, false);
            its_data.options_.push_back(its_option);
        } else {
            VSOMEIP_WARNING << __func__ << ": Cannot create subscription as "
                    " local unreliable port is zero: ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << "."
                    << std::setw(4) << _eventgroup << "]";
            its_data.entry_ = nullptr;
            its_data.other_ = nullptr;
            return its_data;
        }
    }

    if (its_entry &&_subscription->is_selective()) {
        auto its_selective_option = std::make_shared<selective_option_impl>();
        its_selective_option->set_clients(_subscription->get_clients());
        its_data.options_.push_back(its_selective_option);
    }

    if (its_entry && its_other) {
        its_data.entry_ = its_other;
        its_data.other_ = its_entry;
    }

    return its_data;
}

void
service_discovery_impl::insert_subscription_ack(
        const std::shared_ptr<remote_subscription_ack>& _acknowledgement,
        const std::shared_ptr<eventgroupinfo> &_info, ttl_t _ttl,
        const std::shared_ptr<endpoint_definition> &_target,
        const std::set<client_t> &_clients) {
    std::unique_lock<std::recursive_mutex> its_lock(_acknowledgement->get_lock());
    auto its_message = _acknowledgement->get_current_message();

    auto its_service = _info->get_service();
    auto its_instance = _info->get_instance();
    auto its_eventgroup = _info->get_eventgroup();
    auto its_major = _info->get_major();

    for (const auto& its_entry : its_message->get_entries()) {
        if (its_entry->is_eventgroup_entry()) {
            std::shared_ptr<eventgroupentry_impl> its_eventgroup_entry
                = std::dynamic_pointer_cast<eventgroupentry_impl>(its_entry);
            if (its_eventgroup_entry->get_type()
                    == entry_type_e::SUBSCRIBE_EVENTGROUP_ACK
                    && its_eventgroup_entry->get_service() == its_service
                    && its_eventgroup_entry->get_instance() == its_instance
                    && its_eventgroup_entry->get_eventgroup() == its_eventgroup
                    && its_eventgroup_entry->get_major_version() == its_major
                    && its_eventgroup_entry->get_ttl() == _ttl) {

                if (_ttl > 0) {
                    if (_target) {
                        if (_target->is_reliable()) {
                            if (!its_eventgroup_entry->get_target(true)) {
                                its_eventgroup_entry->add_target(_target);
                            }
                        } else {
                            if (!its_eventgroup_entry->get_target(false)) {
                                its_eventgroup_entry->add_target(_target);
                            }
                        }
                    }
                }

                if (_clients.size() > 1 || (*(_clients.begin())) != 0) {
                    auto its_selective_option = its_eventgroup_entry->get_selective_option();
                    if (its_selective_option)
                        its_selective_option->set_clients(_clients);
                }

                return;
            }
        }
    }

    entry_data_t its_data;

    auto its_entry = std::make_shared<eventgroupentry_impl>();
    its_entry->set_type(entry_type_e::SUBSCRIBE_EVENTGROUP_ACK);
    its_entry->set_service(its_service);
    its_entry->set_instance(its_instance);
    its_entry->set_eventgroup(its_eventgroup);
    its_entry->set_major_version(its_major);
    its_entry->set_reserved(0);
    its_entry->set_counter(0);
    // SWS_SD_00315
    its_entry->set_ttl(_ttl);
    if (_ttl > 0) {
        if (_target) {
            its_entry->add_target(_target);
        }

        boost::asio::ip::address its_address;
        uint16_t its_port;
        if (_info->get_multicast(its_address, its_port)
                && _info->get_threshold() > 0) {
            // SIP_SD_855
            // Only insert a multicast option for eventgroups with multicast threshold > 0
            auto its_option = create_ip_option(its_address, its_port, false);
            its_data.options_.push_back(its_option);
        }
    }

    // Selective
    if (_clients.size() > 1 || (*(_clients.begin())) != 0) {
        auto its_selective_option = std::make_shared<selective_option_impl>();
        static_cast<void>(its_selective_option->set_clients(_clients));

        its_data.options_.push_back(its_selective_option);
    }

    its_data.entry_ = its_entry;
    its_data.other_ = nullptr;

    add_entry_data_to_remote_subscription_ack_msg(_acknowledgement, its_data);
}

bool
service_discovery_impl::send(bool _is_announcing) {
    std::shared_ptr < runtime > its_runtime = runtime_.lock();
    if (its_runtime) {
        std::vector<std::shared_ptr<message_impl> > its_messages;
        std::shared_ptr<message_impl> its_message;

        if (_is_announcing) {
            its_message = std::make_shared<message_impl>();
            its_messages.push_back(its_message);

            std::lock_guard<std::mutex> its_lock(offer_mutex_);
            services_t its_offers = host_->get_offered_services();
            insert_offer_entries(its_messages, its_offers, false);

            // Serialize and send
            return send(its_messages);
        }
    }
    return false;
}

// Interface endpoint_host
void
service_discovery_impl::on_message(
        const byte_t *_data, length_t _length,
        const boost::asio::ip::address &_sender,
        bool _is_multicast) {
#if 0
    std::stringstream msg;
    msg << "sdi::on_message: ";
    for (length_t i = 0; i < _length; ++i)
    msg << std::hex << std::setw(2) << std::setfill('0') << (int)_data[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    std::lock_guard<std::mutex> its_lock(check_ttl_mutex_);
    std::lock_guard<std::mutex> its_session_lock(sessions_received_mutex_);
    std::lock_guard<std::recursive_mutex> its_subscribed_lock(subscribed_mutex_);

    if(is_suspended_) {
        return;
    }

    // ignore all SD messages with source address equal to node's unicast address
    if (!check_source_address(_sender)) {
        return;
    }

    if (_is_multicast) {
        static bool must_start_last_msg_received_timer(true);
        boost::system::error_code ec;

        std::lock_guard<std::mutex> its_lock_inner(last_msg_received_timer_mutex_);
        if (0 < last_msg_received_timer_.cancel(ec) || must_start_last_msg_received_timer) {
            must_start_last_msg_received_timer = false;
            last_msg_received_timer_.expires_from_now(
                    last_msg_received_timer_timeout_, ec);
            last_msg_received_timer_.async_wait(
                    std::bind(&service_discovery_impl::on_last_msg_received_timer_expired,
                              shared_from_this(), std::placeholders::_1));
        }
    }

    current_remote_address_ = _sender;
    std::shared_ptr<message_impl> its_message;
    deserialize_data(_data, _length, its_message);
    if (its_message) {
        // ignore all messages which are sent with invalid header fields
        if(!check_static_header_fields(its_message)) {
            return;
        }

        // Expire all subscriptions / services in case of reboot
        if (is_reboot(_sender, _is_multicast,
                its_message->get_reboot_flag(), its_message->get_session())) {
            VSOMEIP_INFO << "Reboot detected: IP=" << _sender.to_string();
            remove_remote_offer_type_by_ip(_sender);
            host_->expire_subscriptions(_sender);
            host_->expire_services(_sender);
            if (reboot_notification_handler_) {
                ip_address_t ip;
                if (_sender.is_v4()) {
                    ip.address_.v4_ = _sender.to_v4().to_bytes();
                    ip.is_v4_ = true;
                } else {
                    ip.address_.v6_ = _sender.to_v6().to_bytes();
                    ip.is_v4_ = false;
                }
                reboot_notification_handler_(ip);
            }
        }

        session_t start_missing_sessions;
        if (!check_session_id_sequence(_sender, _is_multicast, its_message->get_session(), start_missing_sessions)) {
            std::stringstream log;
            log << "SD messages lost from " << _sender.to_string() << " to ";
            if (_is_multicast) {
                log << sd_multicast_address_.to_string();
            } else {
                log << unicast_.to_string();
            }
            log << " - session_id[" << start_missing_sessions;
            if (its_message->get_session() - start_missing_sessions != 1) {
                log << ":" << its_message->get_session() -1;
            }
            log << "]";
            VSOMEIP_WARNING << log.str();
        }

        std::vector<std::shared_ptr<option_impl> > its_options
            = its_message->get_options();

        std::shared_ptr<runtime> its_runtime = runtime_.lock();
        if (!its_runtime) {
            return;
        }

        auto its_acknowledgement = std::make_shared<remote_subscription_ack>(_sender);

        std::vector<std::shared_ptr<message_impl> > its_resubscribes;
        its_resubscribes.push_back(std::make_shared<message_impl>());

        const message_impl::entries_t& its_entries = its_message->get_entries();
        const message_impl::entries_t::const_iterator its_end = its_entries.end();
        bool is_stop_subscribe_subscribe(false);
        bool force_initial_events(false);

        bool sd_acceptance_queried(false);
        expired_ports_t expired_ports;
        sd_acceptance_state_t accept_state(expired_ports);

        for (auto iter = its_entries.begin(); iter != its_end; iter++) {
            if (!sd_acceptance_queried) {
                sd_acceptance_queried = true;
                if (sd_acceptance_handler_) {
                    accept_state.sd_acceptance_required_
                        = configuration_->is_protected_device(_sender);
                    remote_info_t remote;
                    remote.first_ = ANY_PORT;
                    remote.last_ = ANY_PORT;
                    remote.is_range_ = false;
                    if (_sender.is_v4()) {
                        remote.ip_.address_.v4_ = _sender.to_v4().to_bytes();
                        remote.ip_.is_v4_ = true;
                    } else {
                        remote.ip_.address_.v6_ = _sender.to_v6().to_bytes();
                        remote.ip_.is_v4_ = false;
                    }
                    accept_state.accept_entries_ = sd_acceptance_handler_(remote);
                } else {
                    accept_state.accept_entries_ = true;
                }
            }
            if ((*iter)->is_service_entry()) {
                std::shared_ptr<serviceentry_impl> its_service_entry
                    = std::dynamic_pointer_cast<serviceentry_impl>(*iter);
                bool its_unicast_flag = its_message->get_unicast_flag();
                process_serviceentry(its_service_entry, its_options,
                        its_unicast_flag, its_resubscribes,
                        _is_multicast, accept_state);
            } else {
                std::shared_ptr<eventgroupentry_impl> its_eventgroup_entry
                    = std::dynamic_pointer_cast<eventgroupentry_impl>(*iter);

                bool must_process(true);
                // Do we need to process it?
                if (its_eventgroup_entry->get_type()
                        == entry_type_e::SUBSCRIBE_EVENTGROUP) {
                    must_process = !has_same(iter, its_end, its_options);
                }

                if (must_process) {
                    if (is_stop_subscribe_subscribe) {
                        force_initial_events = true;
                    }
                    is_stop_subscribe_subscribe =
                            check_stop_subscribe_subscribe(iter, its_end, its_options);
                    process_eventgroupentry(its_eventgroup_entry, its_options,
                            its_acknowledgement, _sender, _is_multicast,
                            is_stop_subscribe_subscribe, force_initial_events,
                            accept_state);
                }

            }
        }

        {
            std::unique_lock<std::recursive_mutex> its_lock_inner(its_acknowledgement->get_lock());
            its_acknowledgement->complete();
            // TODO: Check the following logic...
            if (its_acknowledgement->has_subscription()) {
                update_acknowledgement(its_acknowledgement);
            } else {
                if (!its_acknowledgement->is_pending()
                    && !its_acknowledgement->is_done()) {
                    send_subscription_ack(its_acknowledgement);
                }
            }
        }

        // check resubscriptions for validity
        for (auto iter = its_resubscribes.begin(); iter != its_resubscribes.end();) {
            if ((*iter)->get_entries().empty() || (*iter)->get_options().empty()) {
                iter = its_resubscribes.erase(iter);
            } else {
                iter++;
            }
        }
        if (!its_resubscribes.empty()) {
            serialize_and_send(its_resubscribes, _sender);
        }
    } else {
        VSOMEIP_ERROR << "service_discovery_impl::" << __func__ << ": Deserialization error.";
        return;
    }
}

void service_discovery_impl::sent_messages(const byte_t* _data, length_t _size,
                                           const boost::asio::ip::address& _remote_address) {
    std::shared_ptr<message_impl> its_message;
    deserialize_data(_data, _size, its_message);
    if (its_message) {
        const message_impl::entries_t& its_entries = its_message->get_entries();
        check_sent_offers(its_entries, _remote_address);
    }
}

// Entry processing
void service_discovery_impl::check_sent_offers(const message_impl::entries_t& _entries,
                                               const boost::asio::ip::address& _remote_address) const {

    // only the offers messages sent by itself to multicast or unicast will be verified
    // the another messages sent by itself will be ignored here
    // the multicast offers are checked when SD receive its
    // the unicast offers are checked in the send_cbk method, when SD send its
    for (auto iter = _entries.begin(); iter != _entries.end(); iter++) {
        if ((*iter)->get_type() == entry_type_e::OFFER_SERVICE && (*iter)->get_ttl() > 0) {
            auto its_service = (*iter)->get_service();
            auto its_instance = (*iter)->get_instance();

            std::shared_ptr<serviceinfo> its_info =
                    host_->get_offered_service(its_service, its_instance);
            if (its_info) {
                if (_remote_address.is_unspecified()) {
                    // enable proccess remote subscription for the services
                    // SD has already sent the offers for this service to multicast ip
                    its_info->set_accepting_remote_subscriptions(true);
                } else {
                    if (!its_info->is_accepting_remote_subscriptions()) {
                        // enable to proccess remote subscription from remote ip for the services
                        its_info->add_remote_ip(_remote_address.to_string());
                    }
                }
            }
        }
    }
}

void service_discovery_impl::process_serviceentry(
        std::shared_ptr<serviceentry_impl>& _entry,
        const std::vector<std::shared_ptr<option_impl>>& _options, bool _unicast_flag,
        std::vector<std::shared_ptr<message_impl>>& _resubscribes, bool _received_via_multicast,
        const sd_acceptance_state_t& _sd_ac_state) {

    // Read service info from entry
    entry_type_e its_type = _entry->get_type();
    service_t its_service = _entry->get_service();
    instance_t its_instance = _entry->get_instance();
    major_version_t its_major = _entry->get_major_version();
    minor_version_t its_minor = _entry->get_minor_version();
    ttl_t its_ttl = _entry->get_ttl();

    // Read address info from options
    boost::asio::ip::address its_reliable_address;
    uint16_t its_reliable_port(ILLEGAL_PORT);

    boost::asio::ip::address its_unreliable_address;
    uint16_t its_unreliable_port(ILLEGAL_PORT);

    for (auto i : { 1, 2 }) {
        for (auto its_index : _entry->get_options(uint8_t(i))) {
            if( _options.size() > its_index ) {
                std::shared_ptr < option_impl > its_option = _options[its_index];

                switch (its_option->get_type()) {
                case option_type_e::IP4_ENDPOINT: {
                    std::shared_ptr < ipv4_option_impl > its_ipv4_option =
                            std::dynamic_pointer_cast < ipv4_option_impl
                                    > (its_option);

                    boost::asio::ip::address_v4 its_ipv4_address(
                            its_ipv4_option->get_address());

                    if (its_ipv4_option->get_layer_four_protocol()
                            == layer_four_protocol_e::UDP) {


                        its_unreliable_address = its_ipv4_address;
                        its_unreliable_port = its_ipv4_option->get_port();
                    } else {
                        its_reliable_address = its_ipv4_address;
                        its_reliable_port = its_ipv4_option->get_port();
                    }
                    break;
                }
                case option_type_e::IP6_ENDPOINT: {
                    std::shared_ptr < ipv6_option_impl > its_ipv6_option =
                            std::dynamic_pointer_cast < ipv6_option_impl
                                    > (its_option);

                    boost::asio::ip::address_v6 its_ipv6_address(
                            its_ipv6_option->get_address());

                    if (its_ipv6_option->get_layer_four_protocol()
                            == layer_four_protocol_e::UDP) {
                        its_unreliable_address = its_ipv6_address;
                        its_unreliable_port = its_ipv6_option->get_port();
                    } else {
                        its_reliable_address = its_ipv6_address;
                        its_reliable_port = its_ipv6_option->get_port();
                    }
                    break;
                }
                case option_type_e::IP4_MULTICAST:
                case option_type_e::IP6_MULTICAST:
                    break;
                case option_type_e::CONFIGURATION:
                    break;
                case option_type_e::UNKNOWN:
                default:
                    VSOMEIP_ERROR << __func__ << ": Unsupported service option";
                    break;
                }
            }
        }
    }

    if (0 < its_ttl) {
        switch (its_type) {
        case entry_type_e::FIND_SERVICE:
            process_findservice_serviceentry(its_service, its_instance, its_major, its_minor,
                                             _unicast_flag);
            break;
        case entry_type_e::OFFER_SERVICE:
            process_offerservice_serviceentry(its_service, its_instance, its_major, its_minor,
                                              its_ttl, its_reliable_address, its_reliable_port,
                                              its_unreliable_address, its_unreliable_port,
                                              _resubscribes, _received_via_multicast, _sd_ac_state);
            break;
        case entry_type_e::UNKNOWN:
        default:
            VSOMEIP_ERROR << __func__ << ": Unsupported service entry type";
        }
    } else if (its_type != entry_type_e::FIND_SERVICE
               && (_sd_ac_state.sd_acceptance_required_ || _sd_ac_state.accept_entries_)) {
        // stop sending find service in repetition phase
        update_request(its_service, its_instance);

        remove_remote_offer_type(its_service, its_instance,
                                 its_reliable_address, its_reliable_port,
                                 its_unreliable_address, its_unreliable_port);
        remove_subscriptions(its_service, its_instance);
        if (!is_diagnosis_ && !is_suspended_) {
            host_->del_routing_info(its_service, its_instance,
                                    (its_reliable_port != ILLEGAL_PORT),
                                    (its_unreliable_port != ILLEGAL_PORT));
        }
    }
}

void service_discovery_impl::process_offerservice_serviceentry(
        service_t _service, instance_t _instance, major_version_t _major, minor_version_t _minor,
        ttl_t _ttl, const boost::asio::ip::address& _reliable_address, uint16_t _reliable_port,
        const boost::asio::ip::address& _unreliable_address, uint16_t _unreliable_port,
        std::vector<std::shared_ptr<message_impl>>& _resubscribes, bool _received_via_multicast,
        const sd_acceptance_state_t& _sd_ac_state) {
    std::shared_ptr<runtime> its_runtime = runtime_.lock();
    if (!its_runtime)
        return;

    bool is_secure = configuration_->is_secure_service(_service, _instance);
    if (is_secure &&
            ((_reliable_port != ILLEGAL_PORT &&
                    !configuration_->is_secure_port(_reliable_address, _reliable_port, true))
             ||  (_unreliable_port != ILLEGAL_PORT
                     && !configuration_->is_secure_port(_unreliable_address, _unreliable_port, false)))) {

        VSOMEIP_WARNING << __func__ << ": Ignoring offer of ["
                << std::hex << std::setfill('0')
                << std::setw(4) << _service << "." << std::setw(4) << _instance
                << "]";
        return;
    }

    // stop sending find service in repetition phase
    update_request(_service, _instance);

    const reliability_type_e offer_type = configuration_->get_reliability_type(
        _reliable_address, _reliable_port, _unreliable_address,_unreliable_port);

    if (offer_type == reliability_type_e::RT_UNKNOWN) {
        VSOMEIP_WARNING << __func__ << ": Unknown remote offer type ["
                << std::hex << std::setfill('0')
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "]";
        return; // Unknown remote offer type --> no way to access it!
    }

    if (_sd_ac_state.sd_acceptance_required_) {

        auto expire_subscriptions_and_services =
                [this, &_sd_ac_state](const boost::asio::ip::address& _address,
                                      std::uint16_t _port, bool _reliable) {
            const auto its_port_pair = std::make_pair(_reliable, _port);
            if (_sd_ac_state.expired_ports_.find(its_port_pair) ==
                    _sd_ac_state.expired_ports_.end()) {
                VSOMEIP_WARNING << "service_discovery_impl::" << __func__
                        << ": Do not accept offer from "
                        << _address.to_string() << ":"
                        << std::dec << _port << " reliable=" << _reliable;
                remove_remote_offer_type_by_ip(_address, _port, _reliable);
                host_->expire_subscriptions(_address, _port, _reliable);
                host_->expire_services(_address, _port, _reliable);
                _sd_ac_state.expired_ports_.insert(its_port_pair);
            }
        };

        // return if the registered sd_acceptance handler returned false
        // and for the provided port sd_acceptance is necessary
        switch (offer_type) {
            case reliability_type_e::RT_UNRELIABLE:
                if (!_sd_ac_state.accept_entries_
                        && configuration_->is_protected_port(
                                _unreliable_address, _unreliable_port, false)) {
                    expire_subscriptions_and_services(_unreliable_address,
                            _unreliable_port, false);
                    return;
                }
                break;
            case reliability_type_e::RT_RELIABLE:
                if (!_sd_ac_state.accept_entries_
                        && configuration_->is_protected_port(
                                _reliable_address, _reliable_port, true)) {
                    expire_subscriptions_and_services(_reliable_address,
                            _reliable_port, true);
                    return;
                }
                break;
            case reliability_type_e::RT_BOTH:
                if (!_sd_ac_state.accept_entries_
                        && (configuration_->is_protected_port(
                                _unreliable_address, _unreliable_port, false)
                                || configuration_->is_protected_port(
                                        _reliable_address, _reliable_port, true))) {
                    expire_subscriptions_and_services(_unreliable_address,
                            _unreliable_port, false);
                    expire_subscriptions_and_services(_reliable_address,
                            _reliable_port, true);
                    return;
                }
                break;
            case reliability_type_e::RT_UNKNOWN:
            default:
                break;
        }
    }

    if (update_remote_offer_type(_service, _instance, offer_type, _reliable_address, _reliable_port,
                                 _unreliable_address, _unreliable_port, _received_via_multicast)) {
        VSOMEIP_WARNING << __func__ << ": Remote offer type changed [" << std::hex << std::setw(4)
                        << std::setfill('0') << _service << "." << std::hex << std::setw(4)
                        << std::setfill('0') << _instance << "]";

        // Only update eventgroup reliability type if it was initially unknown
        auto its_eventgroups = host_->get_subscribed_eventgroups(_service, _instance);
        for (auto eg : its_eventgroups) {
            auto its_info = host_->find_eventgroup(
                    _service, _instance, eg);
            if (its_info) {
                if (its_info->is_reliability_auto_mode()) {
                    if (offer_type != reliability_type_e::RT_UNKNOWN
                            && offer_type != its_info->get_reliability()) {
                        VSOMEIP_WARNING << "sd::" << __func__ << ": eventgroup reliability type changed ["
                                    << std::hex << std::setfill('0')
                                    << std::setw(4) << _service << "."
                                    << std::setw(4) << _instance << "."
                                    << std::setw(4) << eg << "]"
                                    << " using reliability type:  "
                                    << std::setw(4) << static_cast<uint16_t>(offer_type);
                        its_info->set_reliability(offer_type);
                    }
                }
            }
        }
    }

    const bool was_previously_offered_by_unicast = set_offer_multicast_state(
            _service, _instance, offer_type, _reliable_address, _reliable_port, _unreliable_address,
            _unreliable_port, _received_via_multicast);

    // No need to resubscribe for unicast offers
    if (_received_via_multicast) {
        auto found_service = subscribed_.find(_service);
        if (found_service != subscribed_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                if (0 < found_instance->second.size()) {
                    for (const auto& its_eventgroup : found_instance->second) {
                        auto its_subscription = its_eventgroup.second;
                        std::shared_ptr<endpoint> its_reliable, its_unreliable;
                        get_subscription_endpoints(_service, _instance, its_reliable,
                                                   its_unreliable);
                        its_subscription->set_endpoint(its_reliable, true);
                        its_subscription->set_endpoint(its_unreliable, false);
                        for (const auto& its_client : its_subscription->get_clients()) {
                            if (its_subscription->get_state(its_client)
                                == subscription_state_e::ST_ACKNOWLEDGED) {
                                its_subscription->set_state(its_client,
                                                            subscription_state_e::ST_RESUBSCRIBING);
                            } else if (its_subscription->get_state(its_client)
                                               != subscription_state_e::ST_ACKNOWLEDGED
                                       && was_previously_offered_by_unicast) {
                                its_subscription->set_state(its_client,
                                                            subscription_state_e::ST_RESUBSCRIBING);
                            } else {
                                its_subscription->set_state(
                                        its_client,
                                        subscription_state_e::ST_RESUBSCRIBING_NOT_ACKNOWLEDGED);
                            }
                        }
                        const reliability_type_e its_reliability = get_eventgroup_reliability(
                                _service, _instance, its_eventgroup.first, its_subscription);

                        auto its_data =
                                create_eventgroup_entry(_service, _instance, its_eventgroup.first,
                                                        its_subscription, its_reliability);
                        if (its_data.entry_) {
                            add_entry_data(_resubscribes, its_data);
                        }
                        for (const auto its_client : its_subscription->get_clients()) {
                            its_subscription->set_state(its_client,
                                                        subscription_state_e::ST_NOT_ACKNOWLEDGED);
                        }
                    }
                }
            }
        }
    }

    host_->add_routing_info(_service, _instance, _major, _minor,
                            _ttl * get_ttl_factor(_service, _instance, ttl_factor_offers_),
                            _reliable_address, _reliable_port, _unreliable_address,
                            _unreliable_port);
}

void
service_discovery_impl::process_findservice_serviceentry(
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor,
        bool _unicast_flag) {

    if (_instance != ANY_INSTANCE) {
        std::shared_ptr<serviceinfo> its_info = host_->get_offered_service(
                _service, _instance);
        if (its_info) {
            if (_major == ANY_MAJOR || _major == its_info->get_major()) {
                if (_minor == 0xFFFFFFFF || _minor <= its_info->get_minor()) {
                    if (its_info->get_endpoint(false) || its_info->get_endpoint(true)) {
                        send_uni_or_multicast_offerservice(its_info, _unicast_flag);
                    }
                }
            }
        }
    } else {
        std::map<instance_t, std::shared_ptr<serviceinfo>> offered_instances =
                host_->get_offered_service_instances(_service);
        // send back all available instances
        for (const auto &found_instance : offered_instances) {
            auto its_info = found_instance.second;
            if (_major == ANY_MAJOR || _major == its_info->get_major()) {
                if (_minor == 0xFFFFFFFF || _minor <= its_info->get_minor()) {
                    if (its_info->get_endpoint(false) || its_info->get_endpoint(true)) {
                        send_uni_or_multicast_offerservice(its_info, _unicast_flag);
                    }
                }
            }
        }
    }
}

void
service_discovery_impl::send_unicast_offer_service(
        const std::shared_ptr<const serviceinfo> &_info) {
    std::shared_ptr<runtime> its_runtime = runtime_.lock();
    if (!its_runtime) {
        return;
    }

    auto its_offer_message(std::make_shared<message_impl>());
    std::vector<std::shared_ptr<message_impl> > its_messages;
    its_messages.push_back(its_offer_message);

    insert_offer_service(its_messages, _info);

    serialize_and_send(its_messages, current_remote_address_);
}

void
service_discovery_impl::send_multicast_offer_service(
        const std::shared_ptr<const serviceinfo> &_info) {
    auto its_offer_message(std::make_shared<message_impl>());
    std::vector<std::shared_ptr<message_impl> > its_messages;
    its_messages.push_back(its_offer_message);

    insert_offer_service(its_messages, _info);

    serialize_and_send(its_messages, current_remote_address_);
}

void
service_discovery_impl::on_endpoint_connected(
        service_t _service, instance_t _instance,
        const std::shared_ptr<endpoint> &_endpoint) {
    std::shared_ptr<runtime> its_runtime = runtime_.lock();
    if (!its_runtime) {
        return;
    }

    // TODO: Simplify this method! It is not clear, why we need to check
    // both endpoints here although the method is always called for a
    // single one.

    std::vector<std::shared_ptr<message_impl> > its_messages;
    its_messages.push_back(std::make_shared<message_impl>());
    boost::asio::ip::address its_address;

    std::shared_ptr<endpoint> its_dummy;
    if (_endpoint->is_reliable())
        get_subscription_address(_endpoint, its_dummy, its_address);
    else
        get_subscription_address(its_dummy, _endpoint, its_address);

    {
        std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
        auto found_service = subscribed_.find(_service);
        if (found_service != subscribed_.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                if (0 < found_instance->second.size()) {
                    for (const auto &its_eventgroup : found_instance->second) {
                        std::shared_ptr<subscription> its_subscription(its_eventgroup.second);
                        if (its_subscription) {
                            if (!its_subscription->is_tcp_connection_established() ||
                                    !its_subscription->is_udp_connection_established()) {
                                const std::shared_ptr<const endpoint> its_reliable_endpoint(
                                        its_subscription->get_endpoint(true));
                                const std::shared_ptr<const endpoint> its_unreliable_endpoint(
                                        its_subscription->get_endpoint(false));
                                if (its_reliable_endpoint && its_reliable_endpoint->is_established()) {
                                    if (its_reliable_endpoint.get() == _endpoint.get()) {
                                        // mark tcp as established
                                        its_subscription->set_tcp_connection_established(true);
                                    }
                                }
                                if (its_unreliable_endpoint && its_unreliable_endpoint->is_established()) {
                                    if (its_unreliable_endpoint.get() == _endpoint.get()) {
                                        // mark udp as established
                                        its_subscription->set_udp_connection_established(true);
                                    }
                                }

                                if ((its_reliable_endpoint && its_unreliable_endpoint &&
                                        its_subscription->is_tcp_connection_established() &&
                                        its_subscription->is_udp_connection_established()) ||
                                        (its_reliable_endpoint && !its_unreliable_endpoint &&
                                                its_subscription->is_tcp_connection_established()) ||
                                                (its_unreliable_endpoint && !its_reliable_endpoint &&
                                                        its_subscription->is_udp_connection_established())) {

                                    std::shared_ptr<endpoint> its_unreliable;
                                    std::shared_ptr<endpoint> its_reliable;
                                    get_subscription_endpoints(_service, _instance,
                                            its_reliable, its_unreliable);
                                    get_subscription_address(its_reliable, its_unreliable, its_address);

                                    its_subscription->set_endpoint(its_reliable, true);
                                    its_subscription->set_endpoint(its_unreliable, false);
                                    for (const auto its_client : its_subscription->get_clients())
                                        its_subscription->set_state(its_client,
                                                subscription_state_e::ST_NOT_ACKNOWLEDGED);

                                    const reliability_type_e its_reliability_type =
                                            get_eventgroup_reliability(_service, _instance, its_eventgroup.first, its_subscription);
                                    auto its_data = create_eventgroup_entry(_service, _instance,
                                            its_eventgroup.first, its_subscription, its_reliability_type);

                                    if (its_data.entry_) {
                                        add_entry_data(its_messages, its_data);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    serialize_and_send(its_messages, its_address);
}

std::shared_ptr<option_impl>
service_discovery_impl::create_ip_option(
        const boost::asio::ip::address &_address, uint16_t _port,
        bool _is_reliable) const {
    std::shared_ptr<option_impl> its_option;
    if (_address.is_v4()) {
        its_option = std::make_shared<ipv4_option_impl>(
                _address, _port, _is_reliable);
    } else {
        its_option = std::make_shared<ipv6_option_impl>(
                _address, _port, _is_reliable);
    }
    return its_option;
}

void
service_discovery_impl::insert_offer_service(
        std::vector<std::shared_ptr<message_impl> > &_messages,
        const std::shared_ptr<const serviceinfo> &_info) {
    entry_data_t its_data;
    its_data.entry_ = its_data.other_ = nullptr;

    std::shared_ptr<endpoint> its_reliable = _info->get_endpoint(true);
    if (its_reliable) {
        auto its_new_option = create_ip_option(unicast_,
                its_reliable->get_local_port(), true);
        its_data.options_.push_back(its_new_option);
    }

    std::shared_ptr<endpoint> its_unreliable = _info->get_endpoint(false);
    if (its_unreliable) {
        auto its_new_option = create_ip_option(unicast_,
                its_unreliable->get_local_port(), false);
        its_data.options_.push_back(its_new_option);
    }

    auto its_entry = std::make_shared<serviceentry_impl>();
    if (its_entry) {
        its_data.entry_ = its_entry;

        its_entry->set_type(entry_type_e::OFFER_SERVICE);
        its_entry->set_service(_info->get_service());
        its_entry->set_instance(_info->get_instance());
        its_entry->set_major_version(_info->get_major());
        its_entry->set_minor_version(_info->get_minor());

        ttl_t its_ttl = _info->get_ttl();
        if (its_ttl > 0)
            its_ttl = ttl_;
        its_entry->set_ttl(its_ttl);

        add_entry_data(_messages, its_data);
    } else {
        VSOMEIP_ERROR << __func__ << ": Failed to create service entry.";
    }
}

void
service_discovery_impl::process_eventgroupentry(
        std::shared_ptr<eventgroupentry_impl> &_entry,
        const std::vector<std::shared_ptr<option_impl> > &_options,
        std::shared_ptr<remote_subscription_ack> &_acknowledgement,
        const boost::asio::ip::address &_sender,
        bool _is_multicast,
        bool _is_stop_subscribe_subscribe, bool _force_initial_events,
        const sd_acceptance_state_t& _sd_ac_state) {

    std::set<client_t> its_clients({0}); // maybe overridden for selectives

    auto its_sender = _acknowledgement->get_target_address();
    auto its_session = _entry->get_owning_message()->get_session();

    service_t its_service = _entry->get_service();
    instance_t its_instance = _entry->get_instance();
    eventgroup_t its_eventgroup = _entry->get_eventgroup();
    entry_type_e its_type = _entry->get_type();
    major_version_t its_major = _entry->get_major_version();
    ttl_t its_ttl = _entry->get_ttl();

    auto its_info = host_->find_eventgroup(
            its_service, its_instance, its_eventgroup);
    if (!its_info) {
        if (entry_type_e::SUBSCRIBE_EVENTGROUP == its_type) {
            // We received a subscription for a non-existing eventgroup.
            // --> Create dummy eventgroupinfo to send Nack.
            its_info = std::make_shared<eventgroupinfo>(its_service, its_instance,
                    its_eventgroup, its_major, its_ttl, VSOMEIP_DEFAULT_MAX_REMOTE_SUBSCRIBERS);
            boost::system::error_code ec;
            VSOMEIP_ERROR << __func__
                    << ": Received a SubscribeEventGroup entry for unknown eventgroup "
                    << " from: " << its_sender.to_string(ec) << " for: ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup
                    << "] session: " << std::setw(4) << its_session << ", ttl: " << its_ttl;
            if (its_ttl > 0) {
                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
            }
        } else {
            // We received a subscription [n]ack for an eventgroup that does not exist.
            // --> Remove subscription.
            unsubscribe(its_service, its_instance, its_eventgroup, VSOMEIP_ROUTING_CLIENT);

            boost::system::error_code ec;
            VSOMEIP_WARNING << __func__
                    << ": Received a SubscribeEventGroup[N]Ack entry for unknown eventgroup "
                    << " from: " << its_sender.to_string(ec) << " for: ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup
                    << "] session: " << std::setw(4) << its_session << ", ttl: " << its_ttl;
        }
        return;
    }

    if (_entry->get_owning_message()->get_return_code() != return_code) {
        boost::system::error_code ec;
        VSOMEIP_ERROR << __func__ << ": Invalid return code in SOMEIP/SD header "
                << its_sender.to_string(ec) << " session: "
                << std::hex << std::setw(4) << std::setfill('0') << its_session;
        if (its_ttl > 0) {
            insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
        }
        return;
    }

    if (its_type == entry_type_e::SUBSCRIBE_EVENTGROUP) {
        if (_is_multicast) {
            boost::system::error_code ec;
            VSOMEIP_ERROR << __func__
                    << ": Received a SubscribeEventGroup entry on multicast address "
                    << its_sender.to_string(ec) << " session: "
                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
            if (its_ttl > 0) {
                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
            }
            return;
        }
        if (_entry->get_num_options(1) == 0
                && _entry->get_num_options(2) == 0) {
            boost::system::error_code ec;
            VSOMEIP_ERROR << __func__
                    << ": Invalid number of options in SubscribeEventGroup entry "
                    << its_sender.to_string(ec) << " session: "
                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
            if (its_ttl > 0) {
                // increase number of required acks by one as number required acks
                // is calculated based on the number of referenced options
                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
            }
            return;
        }
        if (_entry->get_owning_message()->get_options_length() < 12) {
            boost::system::error_code ec;
            VSOMEIP_ERROR << __func__
                    << ": Invalid options length in SOMEIP/SD message "
                    << its_sender.to_string(ec) << " session: "
                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
            if (its_ttl > 0) {
                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
            }
            return;
        }
        if (_options.size()
                 // cast is needed in order to get unsigned type since int will be promoted
                 // by the + operator on 16 bit or higher machines.
                 < static_cast<std::vector<std::shared_ptr<option_impl>>::size_type>(
                     (_entry->get_num_options(1)) + (_entry->get_num_options(2)))) {
            boost::system::error_code ec;
            VSOMEIP_ERROR << __func__
                    << "Fewer options in SOMEIP/SD message than "
                       "referenced in EventGroup entry or malformed option received "
                    << its_sender.to_string(ec) << " session: "
                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
            if (its_ttl > 0) {
                // set to 0 to ensure an answer containing at least this subscribe_nack is sent out
                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
            }
            return;
        }
        if (_entry->get_owning_message()->get_someip_length()
                < _entry->get_owning_message()->get_length()
                && its_ttl > 0) {
            boost::system::error_code ec;
            VSOMEIP_ERROR  << __func__
                    << ": SOME/IP length field in SubscribeEventGroup message header: ["
                    << std::dec << _entry->get_owning_message()->get_someip_length()
                    << "] bytes, is shorter than length of deserialized message: ["
                    << static_cast<uint32_t>(_entry->get_owning_message()->get_length()) << "] bytes. "
                    << its_sender.to_string(ec) << " session: "
                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
            return;
        }
    }

    boost::asio::ip::address its_first_address;
    uint16_t its_first_port(ILLEGAL_PORT);
    bool is_first_reliable(false);
    boost::asio::ip::address its_second_address;
    uint16_t its_second_port(ILLEGAL_PORT);
    bool is_second_reliable(false);

    for (auto i : { 1, 2 }) {
        for (auto its_index : _entry->get_options(uint8_t(i))) {
            std::shared_ptr < option_impl > its_option;
            try {
                its_option = _options.at(its_index);
            } catch(const std::out_of_range&) {
                boost::system::error_code ec;
                VSOMEIP_ERROR << __func__
                        << ": Fewer options in SD message than "
                           "referenced in EventGroup entry for "
                           "option run number: "
                        << i << " "
                        << its_sender.to_string(ec) << " session: "
                        << std::hex << std::setw(4) << std::setfill('0')
                        << its_session;
                if (entry_type_e::SUBSCRIBE_EVENTGROUP == its_type && its_ttl > 0) {
                    insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                }
                return;
            }
            switch (its_option->get_type()) {
            case option_type_e::IP4_ENDPOINT: {
                if (entry_type_e::SUBSCRIBE_EVENTGROUP == its_type) {
                    std::shared_ptr < ipv4_option_impl > its_ipv4_option =
                            std::dynamic_pointer_cast < ipv4_option_impl
                                    > (its_option);

                    boost::asio::ip::address_v4 its_ipv4_address(
                            its_ipv4_option->get_address());
                    if (!check_layer_four_protocol(its_ipv4_option)) {
                        if (its_ttl > 0) {
                            insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                        }
                        return;
                    }

                    if (its_first_port == ILLEGAL_PORT) {
                        its_first_address = its_ipv4_address;
                        its_first_port = its_ipv4_option->get_port();
                        is_first_reliable = (its_ipv4_option->get_layer_four_protocol()
                                             == layer_four_protocol_e::TCP);

                        // reject subscription referencing two conflicting options of same protocol type
                        // ID: SIP_SD_1144
                        if (is_first_reliable == is_second_reliable
                                && its_second_port != ILLEGAL_PORT) {
                            if (its_ttl > 0) {
                                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                            }
                            boost::system::error_code ec;
                            VSOMEIP_ERROR << __func__
                                    << ": Multiple IPv4 endpoint options of same kind referenced! "
                                    << its_sender.to_string(ec) << " session: "
                                    << std::hex << std::setw(4) << std::setfill('0') << its_session
                                    << " is_first_reliable: " << is_first_reliable;
                            return;
                        }

                        if (!check_ipv4_address(its_first_address)
                                || 0 == its_first_port) {
                            if (its_ttl > 0) {
                                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                            }
                            boost::system::error_code ec;
                            VSOMEIP_ERROR << __func__
                                    << ": Invalid port or IP address in first IPv4 endpoint option specified! "
                                    << its_sender.to_string(ec) << " session: "
                                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
                            return;
                        }
                    } else
                    if (its_second_port == ILLEGAL_PORT) {
                        its_second_address = its_ipv4_address;
                        its_second_port = its_ipv4_option->get_port();
                        is_second_reliable = (its_ipv4_option->get_layer_four_protocol()
                                              == layer_four_protocol_e::TCP);

                        // reject subscription referencing two conflicting options of same protocol type
                        // ID: SIP_SD_1144
                        if (is_second_reliable == is_first_reliable
                                && its_first_port != ILLEGAL_PORT) {
                            if (its_ttl > 0) {
                                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                            }
                            boost::system::error_code ec;
                            VSOMEIP_ERROR << __func__
                                    << ": Multiple IPv4 endpoint options of same kind referenced! "
                                    << its_sender.to_string(ec) << " session: "
                                    << std::hex << std::setw(4) << std::setfill('0') << its_session
                                    << " is_second_reliable: " << is_second_reliable;
                            return;
                        }

                        if (!check_ipv4_address(its_second_address)
                                || 0 == its_second_port) {
                            if (its_ttl > 0) {
                                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                            }
                            boost::system::error_code ec;
                            VSOMEIP_ERROR << __func__
                                    << ": Invalid port or IP address in second IPv4 endpoint option specified! "
                                    << its_sender.to_string(ec) << " session: "
                                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
                            return;
                        }
                    } else {
                        // TODO: error message, too many endpoint options!
                    }
                } else {
                    boost::system::error_code ec;
                    VSOMEIP_ERROR << __func__
                            << ": Invalid eventgroup option (IPv4 Endpoint)"
                            << its_sender.to_string(ec) << " session: "
                            << std::hex << std::setw(4) << std::setfill('0') << its_session;
                }
                break;
            }
            case option_type_e::IP6_ENDPOINT: {
                if (entry_type_e::SUBSCRIBE_EVENTGROUP == its_type) {
                    std::shared_ptr < ipv6_option_impl > its_ipv6_option =
                            std::dynamic_pointer_cast < ipv6_option_impl
                                    > (its_option);

                    boost::asio::ip::address_v6 its_ipv6_address(
                            its_ipv6_option->get_address());
                    if (!check_layer_four_protocol(its_ipv6_option)) {
                        if(its_ttl > 0) {
                            insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                        }
                        boost::system::error_code ec;
                        VSOMEIP_ERROR << "Invalid layer 4 protocol type in IPv6 endpoint option specified! "
                                << its_sender.to_string(ec) << " session: "
                                << std::hex << std::setw(4) << std::setfill('0') << its_session;
                        return;
                    }

                    if (its_first_port == ILLEGAL_PORT) {
                        its_first_address = its_ipv6_address;
                        its_first_port = its_ipv6_option->get_port();
                        is_first_reliable = (its_ipv6_option->get_layer_four_protocol()
                                             == layer_four_protocol_e::TCP);

                        if (is_first_reliable == is_second_reliable
                                && its_second_port != ILLEGAL_PORT) {
                            if (its_ttl > 0) {
                                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                            }
                            boost::system::error_code ec;
                            VSOMEIP_ERROR << __func__
                                    << ": Multiple IPv6 endpoint options of same kind referenced! "
                                    << its_sender.to_string(ec) << " session: "
                                    << std::hex << std::setw(4) << std::setfill('0') << its_session
                                    << " is_first_reliable: " << is_first_reliable;
                            return;
                        }
                    } else
                    if (its_second_port == ILLEGAL_PORT) {
                        its_second_address = its_ipv6_address;
                        its_second_port = its_ipv6_option->get_port();
                        is_second_reliable = (its_ipv6_option->get_layer_four_protocol()
                                              == layer_four_protocol_e::TCP);

                        if (is_second_reliable == is_first_reliable
                                && its_first_port != ILLEGAL_PORT) {
                            if (its_ttl > 0) {
                                insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                            }
                            boost::system::error_code ec;
                            VSOMEIP_ERROR << __func__
                                    << ": Multiple IPv6 endpoint options of same kind referenced! "
                                    << its_sender.to_string(ec) << " session: "
                                    << std::hex << std::setw(4) << std::setfill('0') << its_session
                                    << " is_second_reliable: " << is_second_reliable;
                            return;
                        }
                    } else {
                        // TODO: error message, too many endpoint options!
                    }
                } else {
                    boost::system::error_code ec;
                    VSOMEIP_ERROR << __func__
                            << ": Invalid eventgroup option (IPv6 Endpoint) "
                            << its_sender.to_string(ec) << " session: "
                            << std::hex << std::setw(4) << std::setfill('0') << its_session;
                }
                break;
            }
            case option_type_e::IP4_MULTICAST:
                if (entry_type_e::SUBSCRIBE_EVENTGROUP_ACK == its_type) {
                    std::shared_ptr < ipv4_option_impl > its_ipv4_option =
                            std::dynamic_pointer_cast < ipv4_option_impl
                                    > (its_option);

                    boost::asio::ip::address_v4 its_ipv4_address(
                            its_ipv4_option->get_address());

                    if (its_first_port == ILLEGAL_PORT) {
                        its_first_address = its_ipv4_address;
                        its_first_port = its_ipv4_option->get_port();
                    } else
                    if (its_second_port == ILLEGAL_PORT) {
                        its_second_address = its_ipv4_address;
                        its_second_port = its_ipv4_option->get_port();
                    } else {
                        // TODO: error message, too many endpoint options!
                    }
                    // ID: SIP_SD_946, ID: SIP_SD_1144
                    if (its_first_port != ILLEGAL_PORT
                            && its_second_port != ILLEGAL_PORT) {
                        boost::system::error_code ec;
                        VSOMEIP_ERROR << __func__
                                << ": Multiple IPv4 multicast options referenced! "
                                << its_sender.to_string(ec) << " session: "
                                << std::hex << std::setw(4) << std::setfill('0') << its_session;
                        return;
                    }
                } else {
                    boost::system::error_code ec;
                    VSOMEIP_ERROR << __func__
                            << ": Invalid eventgroup option (IPv4 Multicast) "
                            << its_sender.to_string(ec) << " session: "
                            << std::hex << std::setw(4) << std::setfill('0') << its_session;
                }
                break;
            case option_type_e::IP6_MULTICAST:
                if (entry_type_e::SUBSCRIBE_EVENTGROUP_ACK == its_type) {
                    std::shared_ptr < ipv6_option_impl > its_ipv6_option =
                            std::dynamic_pointer_cast < ipv6_option_impl
                                    > (its_option);

                    boost::asio::ip::address_v6 its_ipv6_address(
                            its_ipv6_option->get_address());

                    if (its_first_port == ILLEGAL_PORT) {
                        its_first_address = its_ipv6_address;
                        its_first_port = its_ipv6_option->get_port();
                    } else
                    if (its_second_port == ILLEGAL_PORT) {
                        its_second_address = its_ipv6_address;
                        its_second_port = its_ipv6_option->get_port();
                    } else {
                        // TODO: error message, too many endpoint options!
                    }
                    // ID: SIP_SD_946, ID: SIP_SD_1144
                    if (its_first_port != ILLEGAL_PORT
                            && its_second_port != ILLEGAL_PORT) {
                        boost::system::error_code ec;
                        VSOMEIP_ERROR << __func__
                                << "Multiple IPv6 multicast options referenced! "
                                << its_sender.to_string(ec) << " session: "
                                << std::hex << std::setw(4) << std::setfill('0') << its_session;
                        return;
                    }
                } else {
                    boost::system::error_code ec;
                    VSOMEIP_ERROR << __func__
                            << ": Invalid eventgroup option (IPv6 Multicast) "
                            << its_sender.to_string(ec) << " session: "
                            << std::hex << std::setw(4) << std::setfill('0') << its_session;
                }
                break;
            case option_type_e::CONFIGURATION: {
                break;
            }
            case option_type_e::SELECTIVE: {
                auto its_selective_option
                    = std::dynamic_pointer_cast<selective_option_impl>(its_option);
                if (its_selective_option) {
                    its_clients = its_selective_option->get_clients();
                }
                break;
            }
            case option_type_e::UNKNOWN:
            default:
                boost::system::error_code ec;
                VSOMEIP_WARNING << __func__
                    << ": Unsupported eventgroup option ["
                    << std::hex << static_cast<int>(its_option->get_type()) << "] "
                    << its_sender.to_string(ec) << " session: "
                    << std::hex << std::setw(4) << std::setfill('0') << its_session;
                if (its_ttl > 0) {
                    insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, its_clients);
                    return;
                }
                break;
            }
        }
    }

    if (entry_type_e::SUBSCRIBE_EVENTGROUP == its_type) {
        handle_eventgroup_subscription(
                its_service, its_instance, its_eventgroup, its_major, its_ttl, 0, 0,
                its_first_address, its_first_port, is_first_reliable, its_second_address,
                its_second_port, is_second_reliable, _acknowledgement, _is_stop_subscribe_subscribe,
                _force_initial_events, its_clients, _sd_ac_state, its_info, _sender);
    } else {
        if (entry_type_e::SUBSCRIBE_EVENTGROUP_ACK == its_type) { //this type is used for ACK and NACK messages
            if (its_ttl > 0) {
                handle_eventgroup_subscription_ack(its_service, its_instance,
                        its_eventgroup, its_major, its_ttl, 0,
                        its_clients, _sender,
                        its_first_address, its_first_port);
            } else {
                handle_eventgroup_subscription_nack(its_service, its_instance, its_eventgroup,
                        0, its_clients);
            }
        }
    }
}

void service_discovery_impl::handle_eventgroup_subscription(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup, major_version_t _major,
        ttl_t _ttl, uint8_t _counter, uint16_t _reserved,
        const boost::asio::ip::address& _first_address, uint16_t _first_port,
        bool _is_first_reliable, const boost::asio::ip::address& _second_address,
        uint16_t _second_port, bool _is_second_reliable,
        std::shared_ptr<remote_subscription_ack>& _acknowledgement,
        bool _is_stop_subscribe_subscribe, bool _force_initial_events,
        const std::set<client_t>& _clients, const sd_acceptance_state_t& _sd_ac_state,
        const std::shared_ptr<eventgroupinfo>& _info, const boost::asio::ip::address& _sender) {
    (void)_counter;
    (void)_reserved;

    auto its_messages = _acknowledgement->get_messages();

#ifndef VSOMEIP_ENABLE_COMPAT
    bool reliablility_nack(false);
    if (_info) {
        const bool first_port_set(_first_port != ILLEGAL_PORT);
        const bool second_port_set(_second_port != ILLEGAL_PORT);
        switch (_info->get_reliability()) {
            case reliability_type_e::RT_UNRELIABLE:
                if (!(first_port_set && !_is_first_reliable)
                        && !(second_port_set && !_is_second_reliable)) {
                    reliablility_nack = true;
                }
                break;
            case reliability_type_e::RT_RELIABLE:
                if (!(first_port_set && _is_first_reliable)
                        && !(second_port_set && _is_second_reliable)) {
                    reliablility_nack = true;
                }
                break;
            case reliability_type_e::RT_BOTH:
                if (_first_port == ILLEGAL_PORT || _second_port == ILLEGAL_PORT) {
                    reliablility_nack = true;
                }
                if (_is_first_reliable == _is_second_reliable) {
                    reliablility_nack = true;
                }
                break;
            default:
                break;
        }
    }
    if (reliablility_nack && _ttl > 0) {
        insert_subscription_ack(_acknowledgement, _info, 0, nullptr, _clients);
        boost::system::error_code ec;
        // TODO: Add sender and session id
        VSOMEIP_WARNING << __func__
                << ": Subscription for ["
                << std::hex << std::setfill('0')
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _eventgroup << "]"
                << " not valid: Event configuration ("
                << static_cast<std::uint32_t>(_info->get_reliability())
                << ") does not match the provided endpoint options: "
                << _first_address.to_string(ec) << ":" << std::dec << _first_port << " "
                << _second_address.to_string(ec) << ":" << _second_port;

        return;
    }

#endif

    if (_ttl > 0) {
        std::shared_ptr<serviceinfo> its_info = host_->get_offered_service(_service, _instance);
        bool send_nack = false;
        if (!its_info) {
            send_nack = true;
        } else {
            if (!its_info->is_accepting_remote_subscriptions()) { // offer not sent to multicast ip
                auto its_remote_ips =
                        its_info->get_remote_ip_accepting_sub(); // offer not sent to unicast
                if (its_remote_ips.find(_sender.to_string()) == its_remote_ips.end())
                    send_nack = true;
            }
        }
        if (send_nack) {
            insert_subscription_ack(_acknowledgement, _info, 0, nullptr, _clients);
            return;
        }
    }

    std::shared_ptr<endpoint_definition> its_subscriber;
    std::shared_ptr<endpoint_definition> its_reliable;
    std::shared_ptr<endpoint_definition> its_unreliable;

    // wrong major version
    if (_major != _info->get_major()) {
        // Create a temporary info object with TTL=0 --> send NACK
        auto its_info = std::make_shared<eventgroupinfo>(_service, _instance,
                _eventgroup, _major, 0, VSOMEIP_DEFAULT_MAX_REMOTE_SUBSCRIBERS);
        boost::system::error_code ec;
        // TODO: Add session id
        VSOMEIP_ERROR << __func__
                << ": Requested major version:[" << static_cast<uint32_t>(_major)
                << "] in subscription to service: ["
                << std::hex << std::setfill('0')
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _eventgroup << "]"
                << " does not match with services major version:["
                << static_cast<uint32_t>(_info->get_major()) << "] subscriber: "
                << _first_address.to_string(ec) << ":" << std::dec << _first_port;
        if (_ttl > 0) {
            insert_subscription_ack(_acknowledgement, its_info, 0, nullptr, _clients);
        }
        return;
    } else {
        boost::asio::ip::address its_first_address, its_second_address;
        if (ILLEGAL_PORT != _first_port) {
            uint16_t its_first_port(0);
            its_subscriber = endpoint_definition::get(
                    _first_address, _first_port, _is_first_reliable, _service, _instance);
            if (!_is_first_reliable &&
                _info->get_multicast(its_first_address, its_first_port) &&
                _info->is_sending_multicast()) { // udp multicast
                its_unreliable = endpoint_definition::get(
                    its_first_address, its_first_port, false, _service, _instance);
            } else if (_is_first_reliable) { // tcp unicast
                its_reliable = its_subscriber;
                // check if TCP connection is established by client
                if (_ttl > 0 && !is_tcp_connected(_service, _instance, its_reliable)) {
                    insert_subscription_ack(_acknowledgement, _info, 0, nullptr, _clients);
                    // TODO: Add sender and session id
                    VSOMEIP_ERROR << "TCP connection to target1: ["
                            << its_reliable->get_address().to_string()
                            << ":" << its_reliable->get_port()
                            << "] not established for subscription to: ["
                            << std::hex << std::setfill('0')
                            << std::setw(4) << _service << "."
                            << std::setw(4) << _instance << "."
                            << std::setw(4) << _eventgroup << "] ";
                    return;
                }
            } else { // udp unicast
                its_unreliable = its_subscriber;
            }
        }

        if (ILLEGAL_PORT != _second_port) {
            uint16_t its_second_port(0);
            its_subscriber = endpoint_definition::get(
                    _second_address, _second_port, _is_second_reliable, _service, _instance);
            if (!_is_second_reliable &&
                _info->get_multicast(its_second_address, its_second_port) &&
                _info->is_sending_multicast()) { // udp multicast
                its_unreliable = endpoint_definition::get(
                    its_second_address, its_second_port, false, _service, _instance);
            } else if (_is_second_reliable) { // tcp unicast
                its_reliable = its_subscriber;
                // check if TCP connection is established by client
                if (_ttl > 0 && !is_tcp_connected(_service, _instance, its_reliable)) {
                    insert_subscription_ack(_acknowledgement, _info, 0, nullptr, _clients);
                    // TODO: Add sender and session id
                    VSOMEIP_ERROR << "TCP connection to target2 : ["
                            << its_reliable->get_address().to_string()
                            << ":" << its_reliable->get_port()
                            << "] not established for subscription to: ["
                            << std::hex << std::setfill('0')
                            << std::setw(4) << _service << "."
                            << std::setw(4) << _instance << "."
                            << std::setw(4) << _eventgroup << "] ";
                    return;
                }
            } else { // udp unicast
                its_unreliable = its_subscriber;
            }
        }
    }

    // check if the subscription should be rejected because of sd_acceptance_handling
    if (_ttl > 0 && _sd_ac_state.sd_acceptance_required_) {
        bool insert_nack(false);
        if (_first_port != ILLEGAL_PORT && !_sd_ac_state.accept_entries_
                && configuration_->is_protected_port(_first_address,
                        _first_port, _is_first_reliable)) {
            insert_nack = true;
        }
        if (!insert_nack && _second_port != ILLEGAL_PORT
                && !_sd_ac_state.accept_entries_
                && configuration_->is_protected_port(_second_address,
                        _second_port, _is_second_reliable)) {
            insert_nack = true;
        }
        if (insert_nack) {
            insert_subscription_ack(_acknowledgement, _info, 0, nullptr, _clients);
            return;
        }
    }

    if (its_subscriber) {
        // Create subscription object
        auto its_subscription = std::make_shared<remote_subscription>();
        its_subscription->set_eventgroupinfo(_info);
        its_subscription->set_subscriber(its_subscriber);
        its_subscription->set_reliable(its_reliable);
        its_subscription->set_unreliable(its_unreliable);
        its_subscription->reset(_clients);

        if (_ttl == 0) { // --> unsubscribe
            its_subscription->set_ttl(0);
            if (!_is_stop_subscribe_subscribe) {
                {
                    std::lock_guard<std::mutex> its_lock(pending_remote_subscriptions_mutex_);
                    pending_remote_subscriptions_[its_subscription] = _acknowledgement;
                    _acknowledgement->add_subscription(its_subscription);
                }
                host_->on_remote_unsubscribe(its_subscription);
            }
            return;
        }

        if (_force_initial_events) {
            its_subscription->set_force_initial_events(true);
        }
        its_subscription->set_ttl(_ttl
                * get_ttl_factor(_service, _instance, ttl_factor_subscriptions_));

        {
            std::lock_guard<std::mutex> its_lock(pending_remote_subscriptions_mutex_);
            pending_remote_subscriptions_[its_subscription] = _acknowledgement;
            _acknowledgement->add_subscription(its_subscription);
        }

        host_->on_remote_subscribe(its_subscription,
                std::bind(&service_discovery_impl::update_remote_subscription,
                          shared_from_this(), std::placeholders::_1));
    }
}

void
service_discovery_impl::handle_eventgroup_subscription_nack(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        uint8_t _counter, const std::set<client_t> &_clients) {
    (void)_counter;

    std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
    auto found_service = subscribed_.find(_service);
    if (found_service != subscribed_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                auto its_subscription = found_eventgroup->second;
                for (const auto its_client : _clients) {
                    host_->on_subscribe_nack(its_client,
                            _service, _instance, _eventgroup, ANY_EVENT,
                            PENDING_SUBSCRIPTION_ID); // TODO: This is a dummy call...
                }


                if (!its_subscription->is_selective()) {
                    auto its_reliable = its_subscription->get_endpoint(true);
                    if (its_reliable)
                        its_reliable->restart();
                }
            }
        }
    }
}

void
service_discovery_impl::handle_eventgroup_subscription_ack(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        major_version_t _major, ttl_t _ttl, uint8_t _counter,
        const std::set<client_t> &_clients,
        const boost::asio::ip::address &_sender,
        const boost::asio::ip::address &_address, uint16_t _port) {
    (void)_major;
    (void)_ttl;
    (void)_counter;

    std::lock_guard<std::recursive_mutex> its_lock(subscribed_mutex_);
    auto found_service = subscribed_.find(_service);
    if (found_service != subscribed_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_eventgroup = found_instance->second.find(_eventgroup);
            if (found_eventgroup != found_instance->second.end()) {
                for (const auto its_client : _clients) {
                    if (found_eventgroup->second->get_state(its_client)
                            == subscription_state_e::ST_NOT_ACKNOWLEDGED) {
                        found_eventgroup->second->set_state(its_client,
                            subscription_state_e::ST_ACKNOWLEDGED);
                        host_->on_subscribe_ack(its_client,
                                _service, _instance, _eventgroup,
                                ANY_EVENT, PENDING_SUBSCRIPTION_ID);
                    }
                }
                if (_address.is_multicast()) {
                    host_->on_subscribe_ack_with_multicast(
                            _service, _instance, _sender, _address, _port);
                }
            }
        }
    }
}

bool service_discovery_impl::is_tcp_connected(service_t _service,
         instance_t _instance,
         const std::shared_ptr<endpoint_definition>& its_endpoint) {
    bool is_connected = false;
    std::shared_ptr<serviceinfo> its_info = host_->get_offered_service(_service,
            _instance);
    if (its_info) {
        //get reliable server endpoint
        auto its_reliable_server_endpoint = std::dynamic_pointer_cast<
                tcp_server_endpoint_impl>(its_info->get_endpoint(true));
        if (its_reliable_server_endpoint
                && its_reliable_server_endpoint->is_established_to(its_endpoint)) {
            is_connected = true;
        }
    }
    return is_connected;
}

bool
service_discovery_impl::send(
        const std::vector<std::shared_ptr<message_impl> > &_messages) {

    bool its_result(true);
    std::lock_guard<std::mutex> its_lock(serialize_mutex_);
    for (const auto &m : _messages) {
        if (m->has_entry()) {
            std::pair<session_t, bool> its_session = get_session(unicast_);
            m->set_session(its_session.first);
            m->set_reboot_flag(its_session.second);
            if (host_->send(VSOMEIP_SD_CLIENT, m, true)) {
                increment_session(unicast_);
            }
        } else {
            its_result = false;
        }
    }
    return its_result;
}

bool
service_discovery_impl::serialize_and_send(
        const std::vector<std::shared_ptr<message_impl> > &_messages,
        const boost::asio::ip::address &_address) {
    bool its_result(true);
    if (!_address.is_unspecified()) {
        std::lock_guard<std::mutex> its_lock(serialize_mutex_);
        for (const auto &m : _messages) {
            if (m->has_entry()) {
                std::pair<session_t, bool> its_session = get_session(_address);
                m->set_session(its_session.first);
                m->set_reboot_flag(its_session.second);

                if (serializer_->serialize(m.get())) {
                    if (host_->send_via_sd(endpoint_definition::get(_address, port_,
                            reliable_, m->get_service(), m->get_instance()),
                            serializer_->get_data(), serializer_->get_size(),
                            port_)) {
                        increment_session(_address);
                    }
                } else {
                    VSOMEIP_ERROR << "service_discovery_impl::" << __func__
                            << ": Serialization failed!";
                    its_result = false;
                }
                serializer_->reset();
            } else {
                its_result = false;
            }
        }
    }
    return its_result;
}

void
service_discovery_impl::start_ttl_timer(int _shift) {

    std::lock_guard<std::mutex> its_lock(ttl_timer_mutex_);

    std::chrono::milliseconds its_timeout(ttl_timer_runtime_);
    if (_shift > 0) {
        if (its_timeout.count() > _shift)
            its_timeout -= std::chrono::milliseconds(_shift);

        if (its_timeout.count() > VSOMEIP_MINIMUM_CHECK_TTL_TIMEOUT)
            its_timeout = std::chrono::milliseconds(VSOMEIP_MINIMUM_CHECK_TTL_TIMEOUT);
    }

    boost::system::error_code ec;
    ttl_timer_.expires_from_now(its_timeout, ec);
    ttl_timer_.async_wait(
            std::bind(&service_discovery_impl::check_ttl, shared_from_this(),
                      std::placeholders::_1));
}

void
service_discovery_impl::stop_ttl_timer() {
    std::lock_guard<std::mutex> its_lock(ttl_timer_mutex_);
    boost::system::error_code ec;
    ttl_timer_.cancel(ec);
}

void
service_discovery_impl::check_ttl(const boost::system::error_code &_error) {

    static int its_counter(0); // count the times we were not able to call
                               // update_routing_info
    if (!_error) {
        {
            std::unique_lock<std::mutex> its_lock(check_ttl_mutex_, std::try_to_lock);
            if (its_lock.owns_lock()) {
                its_counter = 0;
                host_->update_routing_info(ttl_timer_runtime_);
            } else {
                its_counter++;
            }
        }
        start_ttl_timer(its_counter * VSOMEIP_MINIMUM_CHECK_TTL_TIMEOUT);
    }
}

bool
service_discovery_impl::check_static_header_fields(
        const std::shared_ptr<const message> &_message) const {
    if(_message->get_protocol_version() != protocol_version) {
        VSOMEIP_ERROR << "Invalid protocol version in SD header";
        return false;
    }
    if(_message->get_interface_version() != interface_version) {
        VSOMEIP_ERROR << "Invalid interface version in SD header";
        return false;
    }
    if(_message->get_message_type() != message_type) {
        VSOMEIP_ERROR << "Invalid message type in SD header";
        return false;
    }
    if(_message->get_return_code() > return_code_e::E_OK
            && _message->get_return_code()< return_code_e::E_UNKNOWN) {
        VSOMEIP_ERROR << "Invalid return code in SD header";
        return false;
    }
    return true;
}

bool
service_discovery_impl::check_layer_four_protocol(
        const std::shared_ptr<const ip_option_impl>& _ip_option) const {
    if (_ip_option->get_layer_four_protocol() == layer_four_protocol_e::UNKNOWN) {
        VSOMEIP_ERROR << "Invalid layer 4 protocol in IP endpoint option";
        return false;
    }
    return true;
}

void
service_discovery_impl::start_subscription_expiration_timer() {
    std::lock_guard<std::mutex> its_lock(subscription_expiration_timer_mutex_);
    start_subscription_expiration_timer_unlocked();
}

void
service_discovery_impl::start_subscription_expiration_timer_unlocked() {
    subscription_expiration_timer_.expires_at(next_subscription_expiration_);
        subscription_expiration_timer_.async_wait(
                std::bind(&service_discovery_impl::expire_subscriptions,
                          shared_from_this(),
                          std::placeholders::_1));
}

void
service_discovery_impl::stop_subscription_expiration_timer() {
    std::lock_guard<std::mutex> its_lock(subscription_expiration_timer_mutex_);
    stop_subscription_expiration_timer_unlocked();
}

void
service_discovery_impl::stop_subscription_expiration_timer_unlocked() {
    subscription_expiration_timer_.cancel();
}

void
service_discovery_impl::expire_subscriptions(
        const boost::system::error_code &_error) {
    if (!_error) {
        next_subscription_expiration_ = host_->expire_subscriptions(false);
        start_subscription_expiration_timer();
    }
}

bool
service_discovery_impl::check_ipv4_address(
        const boost::asio::ip::address& its_address) const {
    //Check unallowed ipv4 address
    bool is_valid = true;

    static const boost::asio::ip::address_v4::bytes_type its_unicast_address =
            unicast_.to_v4().to_bytes();
    const boost::asio::ip::address_v4::bytes_type endpoint_address =
            its_address.to_v4().to_bytes();
    static const boost::asio::ip::address_v4::bytes_type its_netmask =
            configuration_->get_netmask().to_v4().to_bytes();

    //same address as unicast address of DUT not allowed
    if (its_unicast_address == endpoint_address) {
        VSOMEIP_ERROR << "Subscriber's IP address is same as host's address! : "
                << its_address;
        is_valid = false;
    } else {
        const std::uint32_t self    = bithelper::read_uint32_be(&its_unicast_address[0]);
        const std::uint32_t remote  = bithelper::read_uint32_be(&endpoint_address[0]);
        const std::uint32_t netmask = bithelper::read_uint32_be(&its_netmask[0]);

        if ((self & netmask) != (remote & netmask)) {
            VSOMEIP_ERROR<< "Subscriber's IP isn't in the same subnet as host's IP: "
                    << its_address;
            is_valid = false;
        }
    }
    return is_valid;
}

void
service_discovery_impl::offer_service(const std::shared_ptr<serviceinfo> &_info) {
    service_t its_service = _info->get_service();
    service_t its_instance = _info->get_instance();

    std::lock_guard<std::mutex> its_lock(collected_offers_mutex_);
    // check if offer is in map
    bool found(false);
    const auto its_service_it = collected_offers_.find(its_service);
    if (its_service_it != collected_offers_.end()) {
        const auto its_instance_it = its_service_it->second.find(its_instance);
        if (its_instance_it != its_service_it->second.end()) {
            found = true;
        }
    }
    if (!found) {
        collected_offers_[its_service][its_instance] = _info;
    }
}

void
service_discovery_impl::start_offer_debounce_timer(bool _first_start) {
    std::lock_guard<std::mutex> its_lock(offer_debounce_timer_mutex_);
    boost::system::error_code ec;
    if (_first_start) {
        offer_debounce_timer_.expires_from_now(initial_delay_, ec);
    } else {
        offer_debounce_timer_.expires_from_now(offer_debounce_time_, ec);
    }
    if (ec) {
        VSOMEIP_ERROR<< "service_discovery_impl::start_offer_debounce_timer "
        "setting expiry time of timer failed: " << ec.message();
    }
    offer_debounce_timer_.async_wait(
            std::bind(&service_discovery_impl::on_offer_debounce_timer_expired,
                      this, std::placeholders::_1));
}

void
service_discovery_impl::start_find_debounce_timer(bool _first_start) {
    std::lock_guard<std::mutex> its_lock(find_debounce_timer_mutex_);
    boost::system::error_code ec;
    if (_first_start) {
        find_debounce_timer_.expires_from_now(initial_delay_, ec);
    } else {
        find_debounce_timer_.expires_from_now(find_debounce_time_, ec);
    }
    if (ec) {
        VSOMEIP_ERROR<< "service_discovery_impl::start_find_debounce_timer "
        "setting expiry time of timer failed: " << ec.message();
    }
    find_debounce_timer_.async_wait(
            std::bind(
                    &service_discovery_impl::on_find_debounce_timer_expired,
                    this, std::placeholders::_1));
}

// initial delay
void
service_discovery_impl::on_find_debounce_timer_expired(
        const boost::system::error_code &_error) {
    if(_error) { // timer was canceled
        return;
    }
    // Only copy the accumulated requests of the initial wait phase
    // if the sent counter for the request is zero.
    requests_t repetition_phase_finds;
    bool new_finds(false);
    {
        std::lock_guard<std::mutex> its_lock(requested_mutex_);
        for (const auto& its_service : requested_) {
            for (const auto& its_instance : its_service.second) {
                if( its_instance.second->get_sent_counter() == 0) {
                    repetition_phase_finds[its_service.first][its_instance.first] = its_instance.second;
                }
            }
        }
        if (repetition_phase_finds.size()) {
            new_finds = true;
        }
    }

    if (!new_finds) {
        start_find_debounce_timer(false);
        return;
    }

    // Sent out finds for the first time as initial wait phase ended
    std::vector<std::shared_ptr<message_impl>> its_messages;
    auto its_message = std::make_shared<message_impl>();
    its_messages.push_back(its_message);
    // Serialize and send FindService (increments sent counter in requested_ map)
    insert_find_entries(its_messages, repetition_phase_finds);
    send(its_messages);

    std::chrono::milliseconds its_delay(repetitions_base_delay_);
    std::uint8_t its_repetitions(1);

    auto its_timer = std::make_shared<boost::asio::steady_timer>(host_->get_io());
    {
        std::lock_guard<std::mutex> its_lock(find_repetition_phase_timers_mutex_);
        find_repetition_phase_timers_[its_timer] = repetition_phase_finds;
    }

    boost::system::error_code ec;
    its_timer->expires_from_now(its_delay, ec);
    if (ec) {
        VSOMEIP_ERROR<< "service_discovery_impl::on_find_debounce_timer_expired "
        "setting expiry time of timer failed: " << ec.message();
    }
    its_timer->async_wait(
            std::bind(
                    &service_discovery_impl::on_find_repetition_phase_timer_expired,
                    this, std::placeholders::_1, its_timer, its_repetitions,
                    its_delay.count()));
    start_find_debounce_timer(false);
}

void
service_discovery_impl::on_offer_debounce_timer_expired(
        const boost::system::error_code &_error) {
    if(_error) { // timer was canceled
        return;
    }

    // Copy the accumulated offers of the initial wait phase
    services_t repetition_phase_offers;
    bool new_offers(false);
    {
        std::vector<services_t::iterator> non_someip_services;
        std::lock_guard<std::mutex> its_lock(collected_offers_mutex_);
        if (collected_offers_.size()) {
            if (is_diagnosis_) {
                for (services_t::iterator its_service = collected_offers_.begin();
                        its_service != collected_offers_.end(); its_service++) {
                    for (const auto& its_instance : its_service->second) {
                        if (!configuration_->is_someip(
                                its_service->first, its_instance.first)) {
                            non_someip_services.push_back(its_service);
                        }
                    }
                }
                for (auto its_service : non_someip_services) {
                    repetition_phase_offers.insert(*its_service);
                    collected_offers_.erase(its_service);
                }
            } else {
                repetition_phase_offers = collected_offers_;
                collected_offers_.clear();
            }

            new_offers = true;
        }
    }

    if (!new_offers) {
        start_offer_debounce_timer(false);
        return;
    }

    // Sent out offers for the first time as initial wait phase ended
    std::vector<std::shared_ptr<message_impl>> its_messages;
    auto its_message = std::make_shared<message_impl>();
    its_messages.push_back(its_message);
    insert_offer_entries(its_messages, repetition_phase_offers, true);

    // Serialize and send
    send(its_messages);

    std::chrono::milliseconds its_delay(0);
    std::uint8_t its_repetitions(0);
    if (repetitions_max_) {
        // Start timer for repetition phase the first time
        // with 2^0 * repetitions_base_delay
        its_delay = repetitions_base_delay_;
        its_repetitions = 1;
    } else {
        // If repetitions_max is set to zero repetition phase is skipped,
        // therefore wait one cyclic offer delay before entering main phase
        its_delay = cyclic_offer_delay_;
        its_repetitions = 0;
    }

    auto its_timer = std::make_shared<boost::asio::steady_timer>(host_->get_io());

    {
        std::lock_guard<std::mutex> its_lock(repetition_phase_timers_mutex_);
        repetition_phase_timers_[its_timer] = repetition_phase_offers;
    }

    boost::system::error_code ec;
    its_timer->expires_from_now(its_delay, ec);
    if (ec) {
        VSOMEIP_ERROR<< "service_discovery_impl::on_offer_debounce_timer_expired "
        "setting expiry time of timer failed: " << ec.message();
    }
    its_timer->async_wait(
            std::bind(
                    &service_discovery_impl::on_repetition_phase_timer_expired,
                    this, std::placeholders::_1, its_timer, its_repetitions,
                    its_delay.count()));
    start_offer_debounce_timer(false);
}

void
service_discovery_impl::on_repetition_phase_timer_expired(
        const boost::system::error_code &_error,
        const std::shared_ptr<boost::asio::steady_timer>& _timer,
        std::uint8_t _repetition, std::uint32_t _last_delay) {
    if (_error) {
        return;
    }
    if (_repetition == 0) {
        std::lock_guard<std::mutex> its_lock(repetition_phase_timers_mutex_);
        // We waited one cyclic offer delay, the offers can now be sent in the
        // main phase and the timer can be deleted
        move_offers_into_main_phase(_timer);
    } else {
        std::lock_guard<std::mutex> its_lock(repetition_phase_timers_mutex_);
        auto its_timer_pair = repetition_phase_timers_.find(_timer);
        if (its_timer_pair != repetition_phase_timers_.end()) {
            std::chrono::milliseconds new_delay(0);
            std::uint8_t repetition(0);
            bool move_to_main(false);
            if (_repetition <= repetitions_max_) {
                // Sent offers, double time to wait and start timer again.

                new_delay = std::chrono::milliseconds(_last_delay * 2);
                repetition = ++_repetition;
            } else {
                // Repetition phase is now over we have to sleep one cyclic
                // offer delay before it's allowed to sent the offer again.
                // If the last offer was sent shorter than half the
                // configured cyclic_offer_delay_ago the offers are directly
                // moved into the mainphase to avoid potentially sleeping twice
                // the cyclic offer delay before moving the offers in to main
                // phase
                if (last_offer_shorter_half_offer_delay_ago()) {
                    move_to_main = true;
                } else {
                    new_delay = cyclic_offer_delay_;
                    repetition = 0;
                }
            }
            std::vector<std::shared_ptr<message_impl>> its_messages;
            auto its_message = std::make_shared<message_impl>();
            its_messages.push_back(its_message);
            insert_offer_entries(its_messages, its_timer_pair->second, true);

            // Serialize and send
            send(its_messages);
            if (move_to_main) {
                move_offers_into_main_phase(_timer);
                return;
            }
            boost::system::error_code ec;
            its_timer_pair->first->expires_from_now(new_delay, ec);
            if (ec) {
                VSOMEIP_ERROR <<
                "service_discovery_impl::on_repetition_phase_timer_expired "
                "setting expiry time of timer failed: " << ec.message();
            }
            its_timer_pair->first->async_wait(
                    std::bind(
                            &service_discovery_impl::on_repetition_phase_timer_expired,
                            this, std::placeholders::_1, its_timer_pair->first,
                            repetition, new_delay.count()));
        }
    }
}

void
service_discovery_impl::on_find_repetition_phase_timer_expired(
        const boost::system::error_code &_error,
        const std::shared_ptr<boost::asio::steady_timer>& _timer,
        std::uint8_t _repetition, std::uint32_t _last_delay) {
    if (_error) {
        return;
    }

    std::lock_guard<std::mutex> its_lock(find_repetition_phase_timers_mutex_);
    auto its_timer_pair = find_repetition_phase_timers_.find(_timer);
    if (its_timer_pair != find_repetition_phase_timers_.end()) {
        std::chrono::milliseconds new_delay(0);
        std::uint8_t repetition(0);
        if (_repetition <= repetitions_max_) {
            // Sent findService entries in one message, double time to wait and start timer again.
            std::vector<std::shared_ptr<message_impl>> its_messages;
            auto its_message = std::make_shared<message_impl>();
            its_messages.push_back(its_message);
            insert_find_entries(its_messages, its_timer_pair->second);
            send(its_messages);
            new_delay = std::chrono::milliseconds(_last_delay * 2);
            repetition = ++_repetition;
        } else {
            // Repetition phase is now over, erase the timer on next expiry time
            find_repetition_phase_timers_.erase(its_timer_pair);
            return;
        }
        boost::system::error_code ec;
        its_timer_pair->first->expires_from_now(new_delay, ec);
        if (ec) {
            VSOMEIP_ERROR << __func__
                    << "setting expiry time of timer failed: " << ec.message();
        }
        its_timer_pair->first->async_wait(
                std::bind(
                        &service_discovery_impl::on_find_repetition_phase_timer_expired,
                        this, std::placeholders::_1, its_timer_pair->first,
                        repetition, new_delay.count()));
    }
}

void
service_discovery_impl::move_offers_into_main_phase(
        const std::shared_ptr<boost::asio::steady_timer> &_timer) {
    // HINT: make sure to lock the repetition_phase_timers_mutex_ before calling
    // this function set flag on all serviceinfos bound to this timer that they
    // will be included in the cyclic offers from now on
    const auto its_timer = repetition_phase_timers_.find(_timer);
    if (its_timer != repetition_phase_timers_.end()) {
        for (const auto& its_service : its_timer->second) {
            for (const auto& its_instance : its_service.second) {
                its_instance.second->set_is_in_mainphase(true);
            }
        }
        repetition_phase_timers_.erase(_timer);
    }
}

bool
service_discovery_impl::stop_offer_service(
        const std::shared_ptr<serviceinfo> &_info, bool _send) {
    std::lock_guard<std::mutex> its_lock(offer_mutex_);
    _info->set_ttl(0);
    // disable accepting remote subscriptions
    _info->set_accepting_remote_subscriptions(false);
    const service_t its_service = _info->get_service();
    const instance_t its_instance = _info->get_instance();
    bool stop_offer_required(false);
    // Delete from initial phase offers
    {
        std::lock_guard<std::mutex> its_lock_inner(collected_offers_mutex_);
        if (collected_offers_.size()) {
            auto its_service_it = collected_offers_.find(its_service);
            if (its_service_it != collected_offers_.end()) {
                auto its_instance_it = its_service_it->second.find(its_instance);
                if (its_instance_it != its_service_it->second.end()) {
                    if (its_instance_it->second == _info) {
                        its_service_it->second.erase(its_instance_it);

                        if (!collected_offers_[its_service].size()) {
                            collected_offers_.erase(its_service_it);
                        }
                    }
                }
            }
        }
        // No need to sent out a stop offer message here as all services
        // instances contained in the collected offers weren't broadcasted yet
    }

    // Delete from repetition phase offers
    {
        std::lock_guard<std::mutex> its_lock_inner(repetition_phase_timers_mutex_);
        for (auto rpt = repetition_phase_timers_.begin();
                rpt != repetition_phase_timers_.end();) {
            auto its_service_it = rpt->second.find(its_service);
            if (its_service_it != rpt->second.end()) {
                auto its_instance_it = its_service_it->second.find(its_instance);
                if (its_instance_it != its_service_it->second.end()) {
                    if (its_instance_it->second == _info) {
                        its_service_it->second.erase(its_instance_it);
                        stop_offer_required = true;
                        if (!rpt->second[its_service].size()) {
                            rpt->second.erase(its_service);
                        }
                    }
                }
            }
            if (!rpt->second.size()) {
                rpt = repetition_phase_timers_.erase(rpt);
            } else {
                ++rpt;
            }
        }
    }

    if (!_send) {
        // stop offer required
        return (_info->is_in_mainphase() || stop_offer_required);
    } else if(_info->is_in_mainphase() || stop_offer_required) {
        // Send stop offer
        return send_stop_offer(_info);
    }
    return false;
    // sent out NACKs for all pending subscriptions
    // TODO: remote_subscription_not_acknowledge_all(its_service, its_instance);
}

bool
service_discovery_impl::send_stop_offer(const std::shared_ptr<serviceinfo> &_info) {

    if (_info->get_endpoint(false) || _info->get_endpoint(true)) {
        std::vector<std::shared_ptr<message_impl> > its_messages;
        auto its_current_message = std::make_shared<message_impl>();
        its_messages.push_back(its_current_message);

        insert_offer_service(its_messages, _info);

        // Serialize and send
        return send(its_messages);
    }
    return false;
}

bool
service_discovery_impl::send_collected_stop_offers(const std::vector<std::shared_ptr<serviceinfo>> &_infos) {

    std::vector<std::shared_ptr<message_impl> > its_messages;
    auto its_current_message = std::make_shared<message_impl>();
    its_messages.push_back(its_current_message);

    // pack multiple stop offers together
    for (auto its_info : _infos) {
        if (its_info->get_endpoint(false) || its_info->get_endpoint(true)) {
            insert_offer_service(its_messages, its_info);
        }
    }

    // Serialize and send
    return send(its_messages);
}

void
service_discovery_impl::start_main_phase_timer() {
    std::lock_guard<std::mutex> its_lock(main_phase_timer_mutex_);
    boost::system::error_code ec;
    main_phase_timer_.expires_from_now(cyclic_offer_delay_, ec);
    if (ec) {
        VSOMEIP_ERROR<< "service_discovery_impl::start_main_phase_timer "
        "setting expiry time of timer failed: " << ec.message();
    }
    main_phase_timer_.async_wait(
            std::bind(&service_discovery_impl::on_main_phase_timer_expired,
                    this, std::placeholders::_1));
}

void
service_discovery_impl::stop_main_phase_timer() {
    std::scoped_lock<std::mutex> its_lock(main_phase_timer_mutex_);
    boost::system::error_code ec;
    main_phase_timer_.cancel(ec);
}

void
service_discovery_impl::on_main_phase_timer_expired(
        const boost::system::error_code &_error) {
    if (_error) {
        return;
    }
    send(true);
    start_main_phase_timer();
}

void
service_discovery_impl::send_uni_or_multicast_offerservice(
        const std::shared_ptr<const serviceinfo> &_info, bool _unicast_flag) {
    if (_unicast_flag) { // SID_SD_826
        if (last_offer_shorter_half_offer_delay_ago()) { // SIP_SD_89
            send_unicast_offer_service(_info);
        } else { // SIP_SD_90
            send_multicast_offer_service(_info);
        }
    } else { // SID_SD_826
        send_unicast_offer_service(_info);
    }
}

bool
service_discovery_impl::last_offer_shorter_half_offer_delay_ago() {
    // Get remaining time to next offer since last offer
    std::chrono::milliseconds remaining(0);
    {
        std::lock_guard<std::mutex> its_lock(main_phase_timer_mutex_);
        remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                main_phase_timer_.expires_from_now());
    }
    if (std::chrono::milliseconds(0) > remaining) {
        remaining = cyclic_offer_delay_;
    }
    const std::chrono::milliseconds half_cyclic_offer_delay =
            cyclic_offer_delay_ / 2;

    return remaining > half_cyclic_offer_delay;
}

bool
service_discovery_impl::check_source_address(
        const boost::asio::ip::address &its_source_address) const {

   bool is_valid = true;
   // Check if source address is same as nodes unicast address
   if (unicast_ == its_source_address) {
       VSOMEIP_ERROR << "Source address of message is same as DUT's unicast address! : "
               << its_source_address.to_string();
       is_valid = false;
   }
   return is_valid;
}

void
service_discovery_impl::set_diagnosis_mode(const bool _activate) {

    is_diagnosis_ = _activate;
}

bool
service_discovery_impl::get_diagnosis_mode() {

    return is_diagnosis_;
}

void
service_discovery_impl::update_remote_subscription(
        const std::shared_ptr<remote_subscription> &_subscription) {

    if (!_subscription->is_pending() || 0 == _subscription->get_answers()) {
        std::shared_ptr<remote_subscription_ack> its_ack;
        {
            std::lock_guard<std::mutex> its_lock(pending_remote_subscriptions_mutex_);
            auto found_ack = pending_remote_subscriptions_.find(_subscription);
            if (found_ack != pending_remote_subscriptions_.end()) {
                its_ack = found_ack->second;
            }
        }
        if (its_ack) {
            std::unique_lock<std::recursive_mutex> its_lock(its_ack->get_lock());
            update_acknowledgement(its_ack);
        }
    }
}

void
service_discovery_impl::update_acknowledgement(
        const std::shared_ptr<remote_subscription_ack> &_acknowledgement) {

    if (_acknowledgement->is_complete()
        && !_acknowledgement->is_pending()
        && !_acknowledgement->is_done()) {

        send_subscription_ack(_acknowledgement);

        std::lock_guard<std::mutex> its_lock(pending_remote_subscriptions_mutex_);
        for (const auto &its_subscription : _acknowledgement->get_subscriptions())
            pending_remote_subscriptions_.erase(its_subscription);
    }
}

void
service_discovery_impl::update_subscription_expiration_timer(
        const std::vector<std::shared_ptr<message_impl> > &_messages) {
    std::lock_guard<std::mutex> its_lock(subscription_expiration_timer_mutex_);
    const std::chrono::steady_clock::time_point now =
            std::chrono::steady_clock::now();
    stop_subscription_expiration_timer_unlocked();
    for (const auto &m : _messages) {
        for (const auto &e : m->get_entries()) {
            if (e && e->get_type() == entry_type_e::SUBSCRIBE_EVENTGROUP_ACK
                    && e->get_ttl()) {
                const std::chrono::steady_clock::time_point its_expiration = now
                        + std::chrono::seconds(e->get_ttl()
                                * get_ttl_factor(
                                        e->get_service(), e->get_instance(),
                                        ttl_factor_subscriptions_));
                if (its_expiration < next_subscription_expiration_) {
                    next_subscription_expiration_ = its_expiration;
                }
            }
        }
    }
    start_subscription_expiration_timer_unlocked();
}

bool
service_discovery_impl::check_stop_subscribe_subscribe(
        message_impl::entries_t::const_iterator _iter,
        message_impl::entries_t::const_iterator _end,
        const message_impl::options_t& _options) const {

    return (*_iter)->get_ttl() == 0
            && (*_iter)->get_type() == entry_type_e::STOP_SUBSCRIBE_EVENTGROUP
            && has_opposite(_iter, _end, _options);
}

bool
service_discovery_impl::has_opposite(
        message_impl::entries_t::const_iterator _iter,
        message_impl::entries_t::const_iterator _end,
        const message_impl::options_t &_options) const {
    const auto its_entry = std::dynamic_pointer_cast<eventgroupentry_impl>(*_iter);
    auto its_other = std::next(_iter);
    for (; its_other != _end; its_other++) {
        if ((*its_other)->get_type() == entry_type_e::SUBSCRIBE_EVENTGROUP) {
            const auto its_other_entry
                = std::dynamic_pointer_cast<eventgroupentry_impl>(*its_other);
            if ((its_entry->get_ttl() == 0 && its_other_entry->get_ttl() > 0)
                    || (its_entry->get_ttl() > 0 && its_other_entry->get_ttl() == 0)) {
                if (its_entry->matches(*(its_other_entry.get()), _options))
                    return true;
            }
        }
    }
    return false;
}

bool
service_discovery_impl::has_same(
        message_impl::entries_t::const_iterator _iter,
        message_impl::entries_t::const_iterator _end,
        const message_impl::options_t &_options) const {
    const auto its_entry = std::dynamic_pointer_cast<eventgroupentry_impl>(*_iter);
    auto its_other = std::next(_iter);
    for (; its_other != _end; its_other++) {
        if (its_entry->get_type() == (*its_other)->get_type()) {
            const auto its_other_entry
                = std::dynamic_pointer_cast<eventgroupentry_impl>(*its_other);
            if (its_entry->get_ttl() == its_other_entry->get_ttl()
                    && its_entry->matches(*(its_other_entry.get()), _options)) {
                    return true;
            }
        }
    }
    return false;
}

bool
service_discovery_impl::is_subscribed(
        const std::shared_ptr<eventgroupentry_impl> &_entry,
        const message_impl::options_t &_options) const {
    const auto its_service = _entry->get_service();
    const auto its_instance = _entry->get_instance();
    auto its_info = host_->find_eventgroup(
            its_service, its_instance, _entry->get_eventgroup());
    if (its_info) {
        std::shared_ptr<endpoint_definition> its_reliable, its_unreliable;
        for (const auto& o : _options) {
            if (o->get_type() == option_type_e::IP4_ENDPOINT) {
                const auto its_endpoint_option
                    = std::dynamic_pointer_cast<ipv4_option_impl>(o);
                if (its_endpoint_option) {
                    if (its_endpoint_option->get_layer_four_protocol()
                            == layer_four_protocol_e::TCP) {
                        its_reliable = endpoint_definition::get(
                                boost::asio::ip::address_v4(
                                        its_endpoint_option->get_address()),
                                its_endpoint_option->get_port(),
                                true,
                                its_service, its_instance);
                    } else if (its_endpoint_option->get_layer_four_protocol()
                            == layer_four_protocol_e::UDP) {
                        its_unreliable = endpoint_definition::get(
                                boost::asio::ip::address_v4(
                                        its_endpoint_option->get_address()),
                                its_endpoint_option->get_port(),
                                false,
                                its_service, its_instance);
                    }
                }
            } else if (o->get_type() == option_type_e::IP6_ENDPOINT) {
                const auto its_endpoint_option
                    = std::dynamic_pointer_cast<ipv6_option_impl>(o);
                if (its_endpoint_option->get_layer_four_protocol()
                        == layer_four_protocol_e::TCP) {
                    its_reliable = endpoint_definition::get(
                            boost::asio::ip::address_v6(
                                    its_endpoint_option->get_address()),
                            its_endpoint_option->get_port(),
                            true,
                            its_service, its_instance);
                } else if (its_endpoint_option->get_layer_four_protocol()
                        == layer_four_protocol_e::UDP) {
                    its_unreliable = endpoint_definition::get(
                            boost::asio::ip::address_v6(
                                    its_endpoint_option->get_address()),
                            its_endpoint_option->get_port(),
                            false,
                            its_service, its_instance);
                }
            }
        }
        if (its_reliable || its_unreliable) {
            for (const auto& its_subscription : its_info->get_remote_subscriptions()) {
                if ((!its_reliable || its_subscription->get_reliable() == its_reliable)
                        && (!its_unreliable || its_subscription->get_unreliable() == its_unreliable)) {
                    return true;
                }
            }
        }
    }
    return false;
}

configuration::ttl_factor_t
service_discovery_impl::get_ttl_factor(
        service_t _service, instance_t _instance,
        const configuration::ttl_map_t& _ttl_map) const {
    configuration::ttl_factor_t its_ttl_factor(1);
    auto found_service = _ttl_map.find(_service);
    if (found_service != _ttl_map.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            its_ttl_factor = found_instance->second;
        }
    }
    return its_ttl_factor;
}

void
service_discovery_impl::on_last_msg_received_timer_expired(
        const boost::system::error_code &_error) {

    if (!_error) {
        // We didn't receive a multicast message within 110% of the cyclic_offer_delay_
        VSOMEIP_WARNING << "Didn't receive a multicast SD message for " <<
                std::dec << last_msg_received_timer_timeout_.count() << "ms.";

        // Rejoin multicast group
        if (endpoint_ && !reliable_) {
            auto its_server_endpoint
                = std::dynamic_pointer_cast<udp_server_endpoint_impl>(endpoint_);
            if (its_server_endpoint) {
                its_server_endpoint->leave(sd_multicast_);
                its_server_endpoint->join(sd_multicast_);
            }
        }
        {
            boost::system::error_code ec;
            std::lock_guard<std::mutex> its_lock(last_msg_received_timer_mutex_);
            last_msg_received_timer_.expires_from_now(last_msg_received_timer_timeout_, ec);
            last_msg_received_timer_.async_wait(
                    std::bind(
                            &service_discovery_impl::on_last_msg_received_timer_expired,
                            shared_from_this(), std::placeholders::_1));
        }
    }
}

void
service_discovery_impl::stop_last_msg_received_timer() {
    std::lock_guard<std::mutex> its_lock(last_msg_received_timer_mutex_);
    boost::system::error_code ec;
    last_msg_received_timer_.cancel(ec);
}

reliability_type_e
service_discovery_impl::get_remote_offer_type(
        service_t _service, instance_t _instance) const {
    std::lock_guard<std::mutex> its_lock(remote_offer_types_mutex_);
    auto found_si = remote_offer_types_.find(std::make_pair(_service, _instance));
    if (found_si != remote_offer_types_.end()) {
        return found_si->second;
    }
    return reliability_type_e::RT_UNKNOWN;
}

reliability_type_e
service_discovery_impl::get_remote_offer_type(
        const std::shared_ptr<subscription> &_subscription) const {
    bool has_reliable = (_subscription->get_endpoint(true) != nullptr);
    bool has_unreliable = (_subscription->get_endpoint(false) != nullptr);

    return (has_reliable ?
                (has_unreliable ?
                        reliability_type_e::RT_BOTH :
                        reliability_type_e::RT_RELIABLE) :
                (has_unreliable ?
                        reliability_type_e::RT_UNRELIABLE :
                        reliability_type_e::RT_UNKNOWN));
}


bool service_discovery_impl::update_remote_offer_type(
        service_t _service, instance_t _instance, reliability_type_e _offer_type,
        const boost::asio::ip::address& _reliable_address, std::uint16_t _reliable_port,
        const boost::asio::ip::address& _unreliable_address, std::uint16_t _unreliable_port,
        bool _received_via_multicast) {
    bool ret(false);
    std::lock_guard<std::mutex> its_lock(remote_offer_types_mutex_);
    const remote_offer_info_t its_service_instance(_service, _instance, _received_via_multicast);
    auto found_si = remote_offer_types_.find(its_service_instance.service_info);
    if (found_si != remote_offer_types_.end()) {
        if (found_si->second != _offer_type ) {
            found_si->second = _offer_type;
            ret = true;
        }
    } else {
        remote_offer_types_[its_service_instance.service_info] = _offer_type;
    }
    switch (_offer_type) {
    case reliability_type_e::RT_UNRELIABLE:
        remote_offers_by_ip_[_unreliable_address][std::make_pair(false, _unreliable_port)].insert(
                its_service_instance);
        break;
    case reliability_type_e::RT_RELIABLE:
        remote_offers_by_ip_[_reliable_address][std::make_pair(true, _reliable_port)].insert(
                its_service_instance);
        break;
    case reliability_type_e::RT_BOTH:
        remote_offers_by_ip_[_unreliable_address][std::make_pair(false, _unreliable_port)].insert(
                its_service_instance);
        remote_offers_by_ip_[_unreliable_address][std::make_pair(true, _reliable_port)].insert(
                its_service_instance);
        break;
    case reliability_type_e::RT_UNKNOWN:
    default:
        VSOMEIP_WARNING << __func__ << ": unknown offer type [" << std::hex << std::setw(4)
                        << std::setfill('0') << _service << "." << std::hex << std::setw(4)
                        << std::setfill('0') << _instance << "]" << static_cast<int>(_offer_type);
        break;
    }
    return ret;
}

void
service_discovery_impl::remove_remote_offer_type(
        service_t _service, instance_t _instance,
        const boost::asio::ip::address &_reliable_address,
        std::uint16_t _reliable_port,
        const boost::asio::ip::address &_unreliable_address,
        std::uint16_t _unreliable_port) {
    std::lock_guard<std::mutex> its_lock(remote_offer_types_mutex_);
    const remote_offer_info_t its_service_instance(_service, _instance);

    remote_offer_types_.erase(its_service_instance.service_info);

    auto delete_from_remote_offers_by_ip = [&](const boost::asio::ip::address& _address,
                                               std::uint16_t _port, bool _reliable) {
        const auto found_address = remote_offers_by_ip_.find(_address);
        if (found_address != remote_offers_by_ip_.end()) {
            auto found_port = found_address->second.find(std::make_pair(_reliable, _port));
            if (found_port != found_address->second.end()) {
                if (found_port->second.erase(its_service_instance)) {
                    if (found_port->second.empty()) {
                        found_address->second.erase(found_port);
                        if (found_address->second.empty()) {
                            remote_offers_by_ip_.erase(found_address);
                        }
                    }
                }
            }
        }
    };
    if (_reliable_port != ILLEGAL_PORT) {
        delete_from_remote_offers_by_ip(_reliable_address, _reliable_port,
                true);
    }
    if (_unreliable_port != ILLEGAL_PORT) {
        delete_from_remote_offers_by_ip(_unreliable_address, _unreliable_port,
                false);
    }
}

void service_discovery_impl::remove_remote_offer_type_by_ip(
        const boost::asio::ip::address &_address) {
    remove_remote_offer_type_by_ip(_address, ANY_PORT, false);
}

void service_discovery_impl::remove_remote_offer_type_by_ip(
        const boost::asio::ip::address &_address, std::uint16_t _port, bool _reliable) {
    std::lock_guard<std::mutex> its_lock(remote_offer_types_mutex_);
    const auto found_address = remote_offers_by_ip_.find(_address);
    if (found_address != remote_offers_by_ip_.end()) {
        if (_port == ANY_PORT) {
            for (const auto& port : found_address->second) {
                for (const auto& si : port.second) {
                    remote_offer_types_.erase(si.service_info);
                }
            }
            remote_offers_by_ip_.erase(_address);
        } else {
            const auto its_port_reliability = std::make_pair(_reliable, _port);
            const auto found_port = found_address->second.find(its_port_reliability);
            if (found_port != found_address->second.end()) {
                for (const auto& si : found_port->second) {
                    remote_offer_types_.erase(si.service_info);
                }
                found_address->second.erase(found_port);
                if (found_address->second.empty()) {
                    remote_offers_by_ip_.erase(found_address);
                }
            }
        }
    }
}

bool service_discovery_impl::set_offer_multicast_state(
        service_t _service, instance_t _instance, reliability_type_e _offer_type,
        const boost::asio::ip::address& _reliable_address, port_t _reliable_port,
        const boost::asio::ip::address& _unreliable_address, std::uint16_t _unreliable_port,
        bool _received_via_multicast) {

    bool was_unicast = false;

    auto check_offer_info = [this, &was_unicast, _received_via_multicast](
                                    const boost::asio::ip::address& address, bool reliable,
                                    port_t port, service_t service_id, instance_t instance_id) {
        auto found_address = remote_offers_by_ip_.find(address);
        if (found_address != remote_offers_by_ip_.end()) {
            auto found_port = found_address->second.find(std::make_pair(reliable, port));
            if (found_port != found_address->second.end()) {
                auto found_offer_info = found_port->second.find({service_id, instance_id});
                if (found_offer_info != found_port->second.end()) {
                    if (!found_offer_info->offer_received_via_multicast) {
                        was_unicast = true;
                        found_offer_info->offer_received_via_multicast = _received_via_multicast;
                    }
                }
            }
        }
    };

    switch (_offer_type) {
    case reliability_type_e::RT_UNRELIABLE:
        check_offer_info(_unreliable_address, false, _unreliable_port, _service, _instance);
        break;
    case reliability_type_e::RT_RELIABLE:
        check_offer_info(_reliable_address, true, _reliable_port, _service, _instance);
        break;
    case reliability_type_e::RT_BOTH:
        check_offer_info(_unreliable_address, false, _unreliable_port, _service, _instance);
        check_offer_info(_reliable_address, true, _reliable_port, _service, _instance);
        break;
    case reliability_type_e::RT_UNKNOWN:
    default:
        VSOMEIP_WARNING << __func__ << ": unknown offer type [" << std::hex << std::setw(4)
                        << std::setfill('0') << _service << "." << std::hex << std::setw(4)
                        << std::setfill('0') << _instance << "]" << static_cast<int>(_offer_type);
        break;
    }

    return was_unicast;
}

std::shared_ptr<subscription>
service_discovery_impl::create_subscription(major_version_t _major, ttl_t _ttl,
                                            const std::shared_ptr<endpoint>& _reliable,
                                            const std::shared_ptr<endpoint>& _unreliable,
                                            const std::shared_ptr<eventgroupinfo>& _info) const {
    auto its_subscription = std::make_shared<subscription>();
    its_subscription->set_major(_major);
    its_subscription->set_ttl(_ttl);

    if (_reliable) {
        its_subscription->set_endpoint(_reliable, true);
        its_subscription->set_tcp_connection_established(_reliable->is_established());
    }

    if (_unreliable) {
        its_subscription->set_endpoint(_unreliable, false);
        its_subscription->set_udp_connection_established(_unreliable->is_established());
    }

    // check whether the eventgroup is selective
    its_subscription->set_selective(_info->is_selective());

    its_subscription->set_eventgroupinfo(_info);

    return its_subscription;
}

void
service_discovery_impl::send_subscription_ack(
        const std::shared_ptr<remote_subscription_ack> &_acknowledgement) {

    if (_acknowledgement->is_done())
        return;

    _acknowledgement->done();

    std::uint32_t its_max_answers(1); // Must be 1 as "_acknowledgement" not
                                      // necessarily contains subscriptions
    bool do_not_answer(false);
    std::shared_ptr<remote_subscription> its_parent;

    // Find highest number of necessary answers
    for (const auto& its_subscription : _acknowledgement->get_subscriptions()) {
        auto its_answers = its_subscription->get_answers();
        if (its_answers > its_max_answers) {
            its_max_answers = its_answers;
        } else if (its_answers == 0) {
            do_not_answer = true;
            its_parent = its_subscription->get_parent();
        }
    }

    if (do_not_answer) {
        if (its_parent) {
            std::lock_guard<std::mutex> its_lock(pending_remote_subscriptions_mutex_);
            auto its_parent_ack = pending_remote_subscriptions_[its_parent];
            if (its_parent_ack) {
                for (const auto &its_subscription : its_parent_ack->get_subscriptions()) {
                    if (its_subscription != its_parent)
                        its_subscription->set_answers(its_subscription->get_answers() + 1);
                }
            }
        }
        return;
    }

    // send messages
    for (std::uint32_t i = 0; i < its_max_answers; i++) {
        for (const auto &its_subscription : _acknowledgement->get_subscriptions()) {
            if (i < its_subscription->get_answers()) {
                if (its_subscription->get_ttl() > 0) {
                    auto its_info = its_subscription->get_eventgroupinfo();
                    if (its_info) {
                        std::set<client_t> its_acked;
                        std::set<client_t> its_nacked;
                        for (const auto& its_client : its_subscription->get_clients()) {
                            if (its_subscription->get_client_state(its_client)
                                    == remote_subscription_state_e::SUBSCRIPTION_ACKED) {
                                its_acked.insert(its_client);
                            } else {
                                its_nacked.insert(its_client);
                            }
                        }

                        if (0 < its_acked.size()) {
                            insert_subscription_ack(_acknowledgement, its_info,
                                    its_subscription->get_ttl(),
                                    its_subscription->get_subscriber(), its_acked);
                        }

                        if (0 < its_nacked.size()) {
                            insert_subscription_ack(_acknowledgement, its_info,
                                    0,
                                    its_subscription->get_subscriber(), its_nacked);
                        }
                    }
                }
            }
        }

        auto its_messages = _acknowledgement->get_messages();
        serialize_and_send(its_messages, _acknowledgement->get_target_address());
        update_subscription_expiration_timer(its_messages);
    }

    std::this_thread::yield();

    // We might need to send initial events
    for (const auto &its_subscription : _acknowledgement->get_subscriptions()) {
        // Assumption: We do _NOT_ need to check whether this is a child
        // subscription, as this only applies to selective events, which
        // are owned by exclusive event groups.
        if (its_subscription->get_ttl() > 0
                && its_subscription->is_initial()) {
            its_subscription->set_initial(false);
            auto its_info = its_subscription->get_eventgroupinfo();
            if (its_info) {
                its_info->send_initial_events(
                        its_subscription->get_reliable(),
                        its_subscription->get_unreliable());
            }
        }
    }
}

void
service_discovery_impl::add_entry_data(
        std::vector<std::shared_ptr<message_impl> > &_messages,
        const entry_data_t &_data) {
    auto its_current_message = _messages.back();
    const auto is_fitting = its_current_message->add_entry_data(
            _data.entry_, _data.options_, _data.other_);
    if (!is_fitting) {
        its_current_message = std::make_shared<message_impl>();
        (void)its_current_message->add_entry_data(
                _data.entry_, _data.options_, _data.other_);
        _messages.push_back(its_current_message);
    }
}

void
service_discovery_impl::add_entry_data_to_remote_subscription_ack_msg(
        const std::shared_ptr<remote_subscription_ack>& _acknowledgement,
        const entry_data_t &_data) {
    auto its_current_message = _acknowledgement->get_current_message();
    const auto is_fitting = its_current_message->add_entry_data(
            _data.entry_, _data.options_, _data.other_);
    if (!is_fitting) {
        its_current_message = _acknowledgement->add_message();
        (void)its_current_message->add_entry_data(
                _data.entry_, _data.options_, _data.other_);
    }
}

void
service_discovery_impl::register_sd_acceptance_handler(
        const sd_acceptance_handler_t &_handler) {
    sd_acceptance_handler_ = _handler;
}

void
service_discovery_impl::register_reboot_notification_handler(
            const reboot_notification_handler_t &_handler) {
    reboot_notification_handler_ = _handler;
}

reliability_type_e service_discovery_impl::get_eventgroup_reliability(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        const std::shared_ptr<subscription>& _subscription) {
    reliability_type_e its_reliability = reliability_type_e::RT_UNKNOWN;
    auto its_info = _subscription->get_eventgroupinfo().lock();
    if (its_info) {
        its_reliability = its_info->get_reliability();
        if (its_reliability == reliability_type_e::RT_UNKNOWN
                && its_info->is_reliability_auto_mode()) {
            // fallback: determine how service is offered
            // and update reliability type of eventgroup
            its_reliability = get_remote_offer_type(_service, _instance);
            VSOMEIP_WARNING << "sd::" << __func__ << ": couldn't determine eventgroup reliability type for ["
                        << std::hex << std::setfill('0')
                        << std::setw(4) << _service << "."
                        << std::setw(4) << _instance << "."
                        << std::setw(4) << _eventgroup << "]"
                        << " using reliability type:  "
                        << std::setw(4) << static_cast<uint16_t>(its_reliability);
            its_info->set_reliability(its_reliability);
        }
    } else {
        VSOMEIP_WARNING << "sd::" << __func__ << ": couldn't lock eventgroupinfo ["
                << std::hex << std::setfill('0')
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _eventgroup << "] ";
        auto its_eg_info = host_->find_eventgroup(_service, _instance, _eventgroup);
        if (its_eg_info) {
            _subscription->set_eventgroupinfo(its_eg_info);
            its_reliability = its_eg_info->get_reliability();
        }
    }

    if (its_reliability == reliability_type_e::RT_UNKNOWN) {
        VSOMEIP_WARNING << "sd::" << __func__ << ": eventgroup reliability type is unknown ["
                    << std::hex << std::setfill('0')
                    << std::setw(4) << _service << "."
                    << std::setw(4) << _instance << "."
                    << std::setw(4) << _eventgroup << "]";
    }
    return its_reliability;
}

void service_discovery_impl::deserialize_data(const byte_t* _data, const length_t& _size,
                                              std::shared_ptr<message_impl>& _message) {
    std::lock_guard its_lock(deserialize_mutex_);
    deserializer_->set_data(_data, _size);
    _message = std::shared_ptr<message_impl>(deserializer_->deserialize_sd_message());
    deserializer_->reset();
}

}  // namespace sd
}  // namespace vsomeip_v3
