// Copyright (C) 2014-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#if __GNUC__ > 11
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
#include <unistd.h>
#endif

#include <climits>
#include <forward_list>
#include <future>
#include <iomanip>
#include <mutex>
#include <thread>
#include <unordered_set>

#include <vsomeip/constants.hpp>
#include <vsomeip/runtime.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/event.hpp"
#include "../include/routing_manager_host.hpp"
#include "../include/routing_manager_client.hpp"
#include "../../configuration/include/configuration.hpp"
#include "../../endpoints/include/netlink_connector.hpp"
#include "../../message/include/deserializer.hpp"
#include "../../message/include/message_impl.hpp"
#include "../../message/include/serializer.hpp"
#include "../../protocol/include/assign_client_command.hpp"
#include "../../protocol/include/assign_client_ack_command.hpp"
#include "../../protocol/include/config_command.hpp"
#include "../../protocol/include/deregister_application_command.hpp"
#include "../../protocol/include/distribute_security_policies_command.hpp"
#include "../../protocol/include/dummy_command.hpp"
#include "../../protocol/include/expire_command.hpp"
#include "../../protocol/include/offer_service_command.hpp"
#include "../../protocol/include/offered_services_request_command.hpp"
#include "../../protocol/include/offered_services_response_command.hpp"
#include "../../protocol/include/ping_command.hpp"
#include "../../protocol/include/pong_command.hpp"
#include "../../protocol/include/register_application_command.hpp"
#include "../../protocol/include/register_events_command.hpp"
#include "../../protocol/include/registered_ack_command.hpp"
#include "../../protocol/include/release_service_command.hpp"
#include "../../protocol/include/remove_security_policy_command.hpp"
#include "../../protocol/include/remove_security_policy_response_command.hpp"
#include "../../protocol/include/request_service_command.hpp"
#include "../../protocol/include/resend_provided_events_command.hpp"
#include "../../protocol/include/routing_info_command.hpp"
#include "../../protocol/include/send_command.hpp"
#include "../../protocol/include/stop_offer_service_command.hpp"
#include "../../protocol/include/subscribe_ack_command.hpp"
#include "../../protocol/include/subscribe_command.hpp"
#include "../../protocol/include/subscribe_nack_command.hpp"
#include "../../protocol/include/unregister_event_command.hpp"
#include "../../protocol/include/unsubscribe_ack_command.hpp"
#include "../../protocol/include/unsubscribe_command.hpp"
#include "../../protocol/include/update_security_credentials_command.hpp"
#include "../../protocol/include/update_security_policy_command.hpp"
#include "../../protocol/include/update_security_policy_response_command.hpp"
#include "../../service_discovery/include/runtime.hpp"
#include "../../security/include/policy.hpp"
#include "../../security/include/policy_manager_impl.hpp"
#include "../../security/include/security.hpp"
#include "../../utility/include/bithelper.hpp"
#include "../../utility/include/utility.hpp"
#ifdef USE_DLT
#include "../../tracing/include/connector_impl.hpp"
#endif

#if defined(__QNX__)
#define HAVE_INET_PTON 1
#include <boost/icl/concept/interval_associator.hpp>
#endif
namespace vsomeip_v3 {

routing_manager_client::routing_manager_client(routing_manager_host *_host,
            bool _client_side_logging,
            const std::set<std::tuple<service_t, instance_t> > & _client_side_logging_filter) :
        routing_manager_base(_host),
        is_connected_(false),
        is_started_(false),
        state_(inner_state_type_e::ST_DEREGISTERED),
        sender_(nullptr),
        receiver_(nullptr),
        register_application_timer_(io_),
        request_debounce_timer_ (io_),
        request_debounce_timer_running_(false),
        client_side_logging_(_client_side_logging),
        client_side_logging_filter_(_client_side_logging_filter)
#if defined(__linux__) || defined(ANDROID)
        , is_local_link_available_(false)
#endif // defined(__linux__) || defined(ANDROID)
{

    char its_hostname[1024];
    if (gethostname(its_hostname, sizeof(its_hostname)) == 0) {
        set_client_host(its_hostname);
    }
}

routing_manager_client::~routing_manager_client() {
}

void routing_manager_client::init() {
    routing_manager_base::init(std::make_shared<endpoint_manager_base>(this, io_, configuration_));
    {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (configuration_->is_local_routing()) {
            sender_ = ep_mgr_->create_local(VSOMEIP_ROUTING_CLIENT);
        } else {
#if defined(__linux__) || defined(ANDROID)
            auto its_guest_address = configuration_->get_routing_guest_address();
            auto its_host_address = configuration_->get_routing_host_address();
            local_link_connector_ = std::make_shared<netlink_connector>(
                    io_, its_guest_address, boost::asio::ip::address(),
                    (its_guest_address != its_host_address));
            // if the guest is in the same node as the routing manager
            // it should not require LINK to be UP to communicate

            if (local_link_connector_) {
                local_link_connector_->register_net_if_changes_handler(
                    std::bind(&routing_manager_client::on_net_state_change,
                        this, std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
            } else {
                VSOMEIP_WARNING << __func__ << ": (" << its_guest_address.to_string() << ":"
                                << its_host_address.to_string() << ")"
                                << " local_link_connector not initialized.";
            }
#else
            receiver_ = ep_mgr_->create_local_server(shared_from_this());
            sender_ = ep_mgr_->create_local(VSOMEIP_ROUTING_CLIENT);
#endif
        }
    }
}

void routing_manager_client::start() {

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    if (configuration_->is_local_routing()) {
#else
    {
#endif // __linux__ || ANDROID
        is_started_ = true;
        {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (!sender_) {
                // application has been stopped and started again
                sender_ = ep_mgr_->create_local(VSOMEIP_ROUTING_CLIENT);
            }
            if (sender_) {
                sender_->start();
            }
        }
#if defined(__linux__) || defined(ANDROID)
    } else {
        if (local_link_connector_)
            local_link_connector_->start();
#endif // __linux__ || ANDROID
    }
}

void routing_manager_client::stop() {
    std::unique_lock<std::mutex> its_lock(state_mutex_);
    if (state_ == inner_state_type_e::ST_REGISTERING) {
        register_application_timer_.cancel();
    }

    const std::chrono::milliseconds its_timeout(configuration_->get_shutdown_timeout());
    while (state_ == inner_state_type_e::ST_REGISTERING) {
        std::cv_status status = state_condition_.wait_for(its_lock, its_timeout);
        if (status == std::cv_status::timeout) {
            VSOMEIP_WARNING << std::hex << std::setw(4) << std::setfill('0') << get_client()
                            << " registering timeout on stop";
            break;
        }
    }

    if (state_ == inner_state_type_e::ST_REGISTERED) {
        deregister_application();
        // Waiting de-register acknowledge to synchronize shutdown
        while (state_ == inner_state_type_e::ST_REGISTERED) {
            std::cv_status status = state_condition_.wait_for(its_lock, its_timeout);
            if (status == std::cv_status::timeout) {
                VSOMEIP_WARNING << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " couldn't deregister application - timeout";
                break;
            }
        }
    }
    is_started_ = false;
    its_lock.unlock();

#if defined(__linux__) || defined(ANDROID)
    if (local_link_connector_)
        local_link_connector_->stop();
#endif

    {
        std::lock_guard<std::mutex> its_lock(request_timer_mutex_);
        request_debounce_timer_.cancel();
    }

    if (receiver_) {
        receiver_->stop();
    }
    receiver_ = nullptr;

    {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->stop();
        }
        // delete the sender
        sender_ = nullptr;
    }

    for (const auto client : ep_mgr_->get_connected_clients()) {
        if (client != VSOMEIP_ROUTING_CLIENT) {
            remove_local(client, true);
        }
    }

    if (configuration_->is_local_routing()) {
        std::stringstream its_client;
        its_client << utility::get_base_path(configuration_->get_network())
                   << std::hex << get_client();
    #ifdef _WIN32
        ::_unlink(its_client.str().c_str());
    #else

        if (-1 == ::unlink(its_client.str().c_str())) {
            VSOMEIP_ERROR<< "routing_manager_proxy::stop unlink failed ("
                    << its_client.str() << "): "<< std::strerror(errno);
        }
    #endif
    }
}

#if defined(__linux__) || defined(ANDROID)
void
routing_manager_client::on_net_state_change(
        bool _is_interface, const std::string &_name, bool _is_available) {

    VSOMEIP_INFO << __func__
        << ": " << std::boolalpha << _is_interface << " "
        << _name << " "
        << std::boolalpha << _is_available;

    if (_is_interface) {
        if (_is_available) {
            if (!is_local_link_available_) {

                is_local_link_available_ = true;

                if (!receiver_)
                    receiver_ = ep_mgr_->create_local_server(shared_from_this());

                if (receiver_) {
                    receiver_->start();
                    is_started_ = true;

                    if (!sender_)
                        sender_ = ep_mgr_->create_local(VSOMEIP_ROUTING_CLIENT);

                    if (sender_) {
                        host_->set_sec_client_port(sender_->get_local_port());
                        sender_->start();
                    }
                }
            }
        } else {
            if (is_local_link_available_) {
                is_started_ = false;

                state_ = inner_state_type_e::ST_DEREGISTERED;

                if (sender_) {
                    on_disconnect(sender_);
                    host_->set_sec_client_port(VSOMEIP_SEC_PORT_UNSET);
                    sender_->stop();
                }

                if (receiver_)
                    receiver_->stop();

                {
                    std::lock_guard<std::mutex> its_lock(local_services_mutex_);
                    local_services_.clear();
                }

                is_local_link_available_ = false;
            }
        }
    }
}
#endif // __linux__ || ANDROID

std::shared_ptr<configuration> routing_manager_client::get_configuration() const {
    return host_->get_configuration();
}

std::string routing_manager_client::get_env(client_t _client) const {

   std::lock_guard<std::mutex> its_known_clients_lock(known_clients_mutex_);
   return get_env_unlocked(_client);
}

std::string routing_manager_client::get_env_unlocked(client_t _client) const {

   auto find_client = known_clients_.find(_client);
   if (find_client != known_clients_.end()) {
       return find_client->second;
   }
   return "";
}

bool routing_manager_client::offer_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {

    if (!routing_manager_base::offer_service(_client, _service, _instance, _major, _minor)) {
        VSOMEIP_WARNING << "routing_manager_client::offer_service,"
                << "routing_manager_base::offer_service returned false";
    }
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        if (state_ == inner_state_type_e::ST_REGISTERED) {
            send_offer_service(_client, _service, _instance, _major, _minor);
        }
        protocol::service offer(_service, _instance, _major, _minor );
        pending_offers_.insert(offer);
    }
    return true;
}

void routing_manager_client::send_offer_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {

    (void)_client;

    protocol::offer_service_command its_offer;
    its_offer.set_client(get_client());
    its_offer.set_service(_service);
    its_offer.set_instance(_instance);
    its_offer.set_major(_major);
    its_offer.set_minor(_minor);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_offer.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": offer_service serialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
    }

}

void routing_manager_client::stop_offer_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {

    (void)_client;

    {
        // Hold the mutex to ensure no placeholder event is created in between.
        std::lock_guard<std::mutex> its_lock(stop_mutex_);

        routing_manager_base::stop_offer_service(_client, _service, _instance, _major, _minor);
        clear_remote_subscriber_count(_service, _instance);

        // Note: The last argument does not matter here as a proxy
        //       does not manage endpoints to the external network.
        clear_service_info(_service, _instance, false);
    }

    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        if (state_ == inner_state_type_e::ST_REGISTERED) {

            protocol::stop_offer_service_command its_command;
            its_command.set_client(get_client());
            its_command.set_service(_service);
            its_command.set_instance(_instance);
            its_command.set_major(_major);
            its_command.set_minor(_minor);

            std::vector<byte_t> its_buffer;
            protocol::error_e its_error;
            its_command.serialize(its_buffer, its_error);

            if (its_error == protocol::error_e::ERROR_OK) {
                std::lock_guard<std::mutex> its_lock(sender_mutex_);
                if (sender_) {
                    sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
                }
            } else {
                VSOMEIP_ERROR << __func__ << ": stop offer serialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            }
        }
        auto it = pending_offers_.begin();
        while (it != pending_offers_.end()) {
            if (it->service_ == _service
             && it->instance_ == _instance) {
                break;
            }
            it++;
        }
        if (it != pending_offers_.end()) pending_offers_.erase(it);
    }
}

void routing_manager_client::request_service(client_t _client,
        service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) {
    routing_manager_base::request_service(_client,
            _service, _instance, _major, _minor);
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        size_t request_debouncing_time = configuration_->get_request_debouncing(host_->get_name());
        protocol::service request = { _service, _instance, _major, _minor };
        if (!request_debouncing_time) {
            if (state_ == inner_state_type_e::ST_REGISTERED) {
                std::set<protocol::service> requests;
                requests.insert(request);
                send_request_services(requests);
            }
            requests_.insert(request);
        } else {
            requests_to_debounce_.insert(request);
            std::lock_guard<std::mutex> its_lock(request_timer_mutex_);
            if (!request_debounce_timer_running_) {
                request_debounce_timer_running_ = true;
                request_debounce_timer_.expires_from_now(std::chrono::milliseconds(request_debouncing_time));
                request_debounce_timer_.async_wait(
                        std::bind(
                                &routing_manager_client::request_debounce_timeout_cbk,
                                std::dynamic_pointer_cast<routing_manager_client>(shared_from_this()),
                                std::placeholders::_1));
            }
        }
    }
}

void routing_manager_client::release_service(client_t _client,
        service_t _service, instance_t _instance) {
    routing_manager_base::release_service(_client, _service, _instance);
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        remove_pending_subscription(_service, _instance, 0xFFFF, ANY_EVENT);

        bool pending(false);
        auto it = requests_to_debounce_.begin();
        while (it != requests_to_debounce_.end()) {
            if (it->service_ == _service
             && it->instance_ == _instance) {
                pending = true;
            }
            it++;
        }
        if (it != requests_to_debounce_.end()) requests_to_debounce_.erase(it);

        if (!pending && state_ == inner_state_type_e::ST_REGISTERED) {
            send_release_service(_client, _service, _instance);
        }

        {
            auto it = requests_.begin();
            while (it != requests_.end()) {
                if (it->service_ == _service
                 && it->instance_ == _instance) {
                    break;
                }
                it++;
            }
            if (it != requests_.end()) requests_.erase(it);
        }
    }
}


void routing_manager_client::register_event(client_t _client,
        service_t _service, instance_t _instance,
        event_t _notifier,
        const std::set<eventgroup_t> &_eventgroups, const event_type_e _type,
        reliability_type_e _reliability,
        std::chrono::milliseconds _cycle, bool _change_resets_cycle,
        bool _update_on_change, epsilon_change_func_t _epsilon_change_func,
        bool _is_provided, bool _is_shadow, bool _is_cache_placeholder) {

    (void)_is_shadow;
    (void)_is_cache_placeholder;

    bool is_cyclic(_cycle != std::chrono::milliseconds::zero());

    const event_data_t registration = {
            _service,
            _instance,
            _notifier,
            _type,
            _reliability,
            _is_provided,
            is_cyclic,
            _eventgroups
    };
    bool is_first(false);
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        is_first = pending_event_registrations_.find(registration)
                                        == pending_event_registrations_.end();
#ifndef VSOMEIP_ENABLE_COMPAT
        if (is_first) {
            pending_event_registrations_.insert(registration);
        }
#else
        bool insert = true;
        if (is_first) {
            for (auto iter = pending_event_registrations_.begin();
                    iter != pending_event_registrations_.end();) {
                if (iter->service_ == _service
                        && iter->instance_ == _instance
                        && iter->notifier_ == _notifier
                        && iter->is_provided_ == _is_provided
                        && iter->type_ == event_type_e::ET_EVENT
                        && _type == event_type_e::ET_SELECTIVE_EVENT) {
                    iter = pending_event_registrations_.erase(iter);
                    iter = pending_event_registrations_.insert(registration).first;
                    is_first = true;
                    insert = false;
                    break;
                } else {
                    iter++;
                }
            }
            if (insert) {
                pending_event_registrations_.insert(registration);
            }
        }
#endif
    }
    if (is_first || _is_provided) {
        routing_manager_base::register_event(_client,
                _service, _instance,
                _notifier,
                _eventgroups, _type, _reliability,
                _cycle, _change_resets_cycle, _update_on_change,
                _epsilon_change_func,
                _is_provided);
    }
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        if (state_ == inner_state_type_e::ST_REGISTERED && is_first) {
            send_register_event(get_client(), _service, _instance,
                    _notifier, _eventgroups, _type, _reliability,
                    _is_provided, is_cyclic);
        }
    }
}

void routing_manager_client::unregister_event(client_t _client,
        service_t _service, instance_t _instance, event_t _notifier,
        bool _is_provided) {

    routing_manager_base::unregister_event(_client, _service, _instance,
            _notifier, _is_provided);

    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        if (state_ == inner_state_type_e::ST_REGISTERED) {

            protocol::unregister_event_command its_command;
            its_command.set_client(get_client());
            its_command.set_service(_service);
            its_command.set_instance(_instance);
            its_command.set_event(_notifier);
            its_command.set_provided(_is_provided);

            std::vector<byte_t> its_buffer;
            protocol::error_e its_error;
            its_command.serialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                std::lock_guard<std::mutex> its_lock(sender_mutex_);
                if (sender_) {
                    sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
                }
            }
        }

        for (auto iter = pending_event_registrations_.begin();
                iter != pending_event_registrations_.end(); ) {
            if (iter->service_ == _service
                    && iter->instance_ == _instance
                    && iter->notifier_ == _notifier
                    && iter->is_provided_ == _is_provided) {
                pending_event_registrations_.erase(iter);
                break;
            } else {
                iter++;
            }
        }
    }
}

bool routing_manager_client::is_field(service_t _service, instance_t _instance,
        event_t _event) const {
    auto event = find_event(_service, _instance, _event);
    if (event && event->is_field()) {
        return true;
    }
    return false;
}

void routing_manager_client::subscribe(
        client_t _client, const vsomeip_sec_client_t *_sec_client,
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, major_version_t _major,
        event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter) {

    (void)_client;

    std::lock_guard<std::mutex> its_lock(state_mutex_);
    if (state_ == inner_state_type_e::ST_REGISTERED && is_available(_service, _instance, _major)) {
        send_subscribe(get_client(), _service, _instance, _eventgroup, _major, _event, _filter );
    }
    subscription_data_t subscription = {
            _service, _instance,
            _eventgroup, _major,
            _event, _filter,
            *_sec_client
    };
    pending_subscriptions_.insert(subscription);
}

void routing_manager_client::send_subscribe(client_t _client,
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, major_version_t _major,
        event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter) {

    if (_event == ANY_EVENT) {
        if (!is_subscribe_to_any_event_allowed(get_sec_client(), _client, _service, _instance, _eventgroup)) {
            VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << _client
                    << " : routing_manager_proxy::subscribe: "
                    << " isn't allowed to subscribe to service/instance/event "
                    << _service << "/" << _instance << "/ANY_EVENT"
                    << " which violates the security policy ~> Skip subscribe!";
            return;
        }
    } else {
        if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                get_sec_client(), _service, _instance, _event)) {
            VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << _client
                    << " : routing_manager_proxy::subscribe: "
                    << " isn't allowed to subscribe to service/instance/event "
                    << _service << "/" << _instance
                    << "/" << _event;
            return;
        }
    }

    protocol::subscribe_command its_command;
    its_command.set_client(_client);
    its_command.set_service(_service);
    its_command.set_instance(_instance);
    its_command.set_eventgroup(_eventgroup);
    its_command.set_major(_major);
    its_command.set_event(_event);
    its_command.set_pending_id(PENDING_SUBSCRIPTION_ID);
    its_command.set_filter(_filter);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        client_t its_target_client = find_local_client(_service, _instance);
        if (its_target_client != VSOMEIP_ROUTING_CLIENT) {
            std::shared_ptr<vsomeip_v3::endpoint> its_target =
                    ep_mgr_->find_or_create_local(its_target_client);
            if (its_target) {
                its_target->send(&its_buffer[0], uint32_t(its_buffer.size()));
            } else {
                VSOMEIP_ERROR << std::hex << std::setfill('0') << __func__
                              << ": no target available to send subscription."
                              << " client=" << std::setw(4) << _client
                              << " service=" << std::setw(4) << _service << "." << std::setw(4)
                              << _instance << "." << std::setw(2)
                              << static_cast<std::uint16_t>(_major) << " event=" << std::setw(4)
                              << _event;
            }
        } else {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
            }
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": subscribe command serialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
    }
}

void routing_manager_client::send_subscribe_nack(client_t _subscriber,
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        event_t _event, remote_subscription_id_t _id) {

    protocol::subscribe_nack_command its_command;
    its_command.set_client(get_client());
    its_command.set_service(_service);
    its_command.set_instance(_instance);
    its_command.set_eventgroup(_eventgroup);
    its_command.set_subscriber(_subscriber);
    its_command.set_event(_event);
    its_command.set_pending_id(_id);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);
    if (its_error == protocol::error_e::ERROR_OK) {
        if (_subscriber != VSOMEIP_ROUTING_CLIENT
                && _id == PENDING_SUBSCRIPTION_ID) {
            auto its_target = ep_mgr_->find_local(_subscriber);
            if (its_target) {
                its_target->send(&its_buffer[0], uint32_t(its_buffer.size()));
                return;
            }
        }
        {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
            }
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": subscribe nack serialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
    }
}

void routing_manager_client::send_subscribe_ack(client_t _subscriber,
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        event_t _event, remote_subscription_id_t _id) {

    protocol::subscribe_ack_command its_command;
    its_command.set_client(get_client());
    its_command.set_service(_service);
    its_command.set_instance(_instance);
    its_command.set_eventgroup(_eventgroup);
    its_command.set_subscriber(_subscriber);
    its_command.set_event(_event);
    its_command.set_pending_id(_id);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);
    if (its_error == protocol::error_e::ERROR_OK) {
        if (_subscriber != VSOMEIP_ROUTING_CLIENT
                && _id == PENDING_SUBSCRIPTION_ID) {
            auto its_target = ep_mgr_->find_local(_subscriber);
            if (its_target) {
                its_target->send(&its_buffer[0], uint32_t(its_buffer.size()));
                return;
            }
        }
        {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
            }
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": subscribe ack serialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
    }
}

void routing_manager_client::unsubscribe(client_t _client,
        const vsomeip_sec_client_t *_sec_client,
    service_t _service, instance_t _instance, eventgroup_t _eventgroup, event_t _event) {

    (void)_client;
    (void)_sec_client;

    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        remove_pending_subscription(_service, _instance, _eventgroup, _event);

        if (state_ == inner_state_type_e::ST_REGISTERED) {

            protocol::unsubscribe_command its_command;
            its_command.set_client(_client);
            its_command.set_service(_service);
            its_command.set_instance(_instance);
            its_command.set_eventgroup(_eventgroup);
            its_command.set_major(ANY_MAJOR);
            its_command.set_event(_event);
            its_command.set_pending_id(PENDING_SUBSCRIPTION_ID);

            std::vector<byte_t> its_buffer;
            protocol::error_e its_error;
            its_command.serialize(its_buffer, its_error);

            if (its_error == protocol::error_e::ERROR_OK) {

                auto its_target = ep_mgr_->find_local(_service, _instance);
                if (its_target) {
                    its_target->send(&its_buffer[0], uint32_t(its_buffer.size()));
                } else {
                    std::lock_guard<std::mutex> its_lock(sender_mutex_);
                    if (sender_) {
                        sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
                    }
                }
            } else {

                VSOMEIP_ERROR << __func__
                        << ": unsubscribe serialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            }
        }
    }
}

bool routing_manager_client::send(client_t _client, const byte_t *_data,
        length_t _size, instance_t _instance, bool _reliable,
        client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
        uint8_t _status_check, bool _sent_from_remote, bool _force) {

    (void)_client;
    (void)_bound_client;
    (void)_sec_client;
    (void)_sent_from_remote;
    bool is_sent(false);
    bool has_remote_subscribers(false);
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        if (state_ != inner_state_type_e::ST_REGISTERED) {
            return false;
        }
    }
    if (client_side_logging_) {
        if (_size > VSOMEIP_MESSAGE_TYPE_POS) {
            service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
            if (client_side_logging_filter_.empty()
                || (1 == client_side_logging_filter_.count(std::make_tuple(its_service, ANY_INSTANCE)))
                || (1 == client_side_logging_filter_.count(std::make_tuple(its_service, _instance)))) {
                method_t its_method   = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);
                session_t its_session = bithelper::read_uint16_be(&_data[VSOMEIP_SESSION_POS_MIN]);
                client_t its_client   = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
                VSOMEIP_INFO << "routing_manager_client::send: ("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << get_client() << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << _instance << "."
                    << std::setw(4) << its_method << ":"
                    << std::setw(4) << its_session << ":"
                    << std::setw(4) << its_client << "] "
                    << "type=" << std::hex << static_cast<std::uint32_t>(_data[VSOMEIP_MESSAGE_TYPE_POS])
                    << " thread=" << std::hex << std::this_thread::get_id();
            }
        } else {
            VSOMEIP_ERROR << "routing_manager_client::send: ("
                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                << "): message too short to log: " << std::dec << _size;
        }
    }
    if (_size > VSOMEIP_MESSAGE_TYPE_POS) {
        std::shared_ptr<endpoint> its_target;
        if (utility::is_request(_data[VSOMEIP_MESSAGE_TYPE_POS])) {
            // Request
            service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);
            client_t its_client = find_local_client(its_service, _instance);
            if (its_client != VSOMEIP_ROUTING_CLIENT) {
                if (is_client_known(its_client)) {
                    its_target = ep_mgr_->find_or_create_local(its_client);
                }
            }
        } else if (!utility::is_notification(_data[VSOMEIP_MESSAGE_TYPE_POS])) {
            // Response
            client_t its_client = bithelper::read_uint16_be(&_data[VSOMEIP_CLIENT_POS_MIN]);
            if (its_client != VSOMEIP_ROUTING_CLIENT) {
                if (is_client_known(its_client)) {
                    its_target = ep_mgr_->find_or_create_local(its_client);
                }
            }
        } else if (utility::is_notification(_data[VSOMEIP_MESSAGE_TYPE_POS]) &&
                _client == VSOMEIP_ROUTING_CLIENT) {
            // notify
            has_remote_subscribers = send_local_notification(get_client(), _data, _size,
                    _instance, _reliable, _status_check, _force);
        } else if (utility::is_notification(_data[VSOMEIP_MESSAGE_TYPE_POS]) &&
                _client != VSOMEIP_ROUTING_CLIENT) {
            // notify_one
            its_target = ep_mgr_->find_local(_client);
            if (its_target) {
#ifdef USE_DLT
                trace::header its_header;
                if (its_header.prepare(nullptr, true, _instance))
                    tc_->trace(its_header.data_, VSOMEIP_TRACE_HEADER_SIZE,
                            _data, _size);
#endif
                return send_local(its_target, get_client(), _data, _size,
                        _instance, _reliable, protocol::id_e::SEND_ID, _status_check);
            }
        }
        // If no direct endpoint could be found
        // or for notifications ~> route to routing_manager_stub
#ifdef USE_DLT
        bool message_to_stub(false);
#endif
        if (!its_target) {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                its_target = sender_;
#ifdef USE_DLT
                message_to_stub = true;
#endif
            } else {
                return false;
            }
        }

        bool send(true);
        protocol::id_e its_command(protocol::id_e::SEND_ID);

        if (utility::is_notification(_data[VSOMEIP_MESSAGE_TYPE_POS])) {
            if (_client != VSOMEIP_ROUTING_CLIENT) {
                its_command = protocol::id_e::NOTIFY_ONE_ID;
            } else {
                its_command = protocol::id_e::NOTIFY_ID;
                // Do we need to deliver a notification to the routing manager?
                // Only for services which already have remote clients subscribed to
                send = has_remote_subscribers;
            }
        }
#ifdef USE_DLT
        else if (!message_to_stub) {
            trace::header its_header;
            if (its_header.prepare(nullptr, true, _instance))
                tc_->trace(its_header.data_, VSOMEIP_TRACE_HEADER_SIZE,
                        _data, _size);
        }
#endif
        if (send) {
            is_sent = send_local(its_target,
                    (its_command == protocol::id_e::NOTIFY_ONE_ID ? _client : get_client()),
                    _data, _size, _instance, _reliable, its_command, _status_check);
        }
    }
    return is_sent;
}

bool routing_manager_client::send_to(const client_t _client,
        const std::shared_ptr<endpoint_definition> &_target,
        std::shared_ptr<message> _message) {

    (void)_client;
    (void)_target;
    (void)_message;

    return false;
}

bool routing_manager_client::send_to(
        const std::shared_ptr<endpoint_definition> &_target,
        const byte_t *_data, uint32_t _size, instance_t _instance) {

    (void)_target;
    (void)_data;
    (void)_size;
    (void)_instance;

    return false;
}

void routing_manager_client::on_connect(const std::shared_ptr<endpoint>& _endpoint) {

    _endpoint->set_connected(true);
    _endpoint->set_established(true);
    {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (_endpoint != sender_) {
            return;
        }
    }
    is_connected_ = true;
    assign_client();
}

void routing_manager_client::on_disconnect(const std::shared_ptr<endpoint>& _endpoint) {
    {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        is_connected_ = !(_endpoint == sender_);
    }
    if (!is_connected_) {
        VSOMEIP_INFO << "routing_manager_client::on_disconnect: Client 0x"
                     << std::hex << std::setw(4) << std::setfill('0') << get_client()
                     << " calling host_->on_state with DEREGISTERED";
        host_->on_state(state_type_e::ST_DEREGISTERED);
    }
}

void routing_manager_client::on_message(
        const byte_t *_data, length_t _size,
        endpoint *_receiver, bool _is_multicast,
        client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
        const boost::asio::ip::address &_remote_address,
        std::uint16_t _remote_port) {

    (void)_receiver;
    (void)_is_multicast;
    (void)_remote_address;
    (void)_remote_port;

#if 0
    std::stringstream msg;
    msg << "rmp::on_message<" << std::hex << get_client() << ">: ";
    for (length_t i = 0; i < _size; ++i)
        msg << std::hex << std::setw(2) << std::setfill('0') << (int)_data[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    protocol::id_e its_id;
    client_t its_client;
    service_t its_service;
    instance_t its_instance;
    eventgroup_t its_eventgroup;
    event_t its_event;
    major_version_t its_major;
    client_t routing_host_id = configuration_->get_id(
            configuration_->get_routing_host_name());
    client_t its_subscriber;
    remote_subscription_id_t its_pending_id(PENDING_SUBSCRIPTION_ID);
    std::uint32_t its_remote_subscriber_count(0);
#ifndef VSOMEIP_DISABLE_SECURITY
    bool is_internal_policy_update(false);
#endif // !VSOMEIP_DISABLE_SECURITY
    std::vector<byte_t> its_buffer(_data, _data + _size);
    protocol::error_e its_error;

    auto its_policy_manager = configuration_->get_policy_manager();
    if (!its_policy_manager)
        return;

    protocol::dummy_command its_dummy_command;
    its_dummy_command.deserialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        its_id = its_dummy_command.get_id();
        its_client = its_dummy_command.get_client();

        bool is_from_routing(false);
        if (configuration_->is_security_enabled()) {
            if (configuration_->is_local_routing()) {
                // if security is enabled, client ID of routing must be configured
                // and credential passing is active. Otherwise bound client is zero by default
                is_from_routing = (_bound_client == routing_host_id);
            } else {
                is_from_routing = (_remote_address == configuration_->get_routing_host_address()
                                && _remote_port == configuration_->get_routing_host_port() + 1);
            }
        } else {
            is_from_routing = (its_client == routing_host_id);
        }

        if (configuration_->is_security_enabled()
                && configuration_->is_local_routing()
                && !is_from_routing && _bound_client != its_client) {
            VSOMEIP_WARNING << "Client " << std::hex << std::setw(4) << std::setfill('0')
                            << get_client() << " received a message with command " << int(its_id)
                            << " from " << std::hex << std::setw(4) << std::setfill('0')
                            << its_client << " which doesn't match the bound client " << std::hex
                            << std::setw(4) << std::setfill('0') << _bound_client
                            << " ~> skip message!";
            return;
        }

        switch (its_id) {
        case protocol::id_e::SEND_ID:
        {
            protocol::send_command its_send_command(protocol::id_e::SEND_ID);
            its_send_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                auto a_deserializer = get_deserializer();
                a_deserializer->set_data(its_send_command.get_message());
                std::shared_ptr<message_impl> its_message(a_deserializer->deserialize_message());
                a_deserializer->reset();
                put_deserializer(a_deserializer);

                if (its_message) {
                    its_message->set_instance(its_send_command.get_instance());
                    its_message->set_reliable(its_send_command.is_reliable());
                    its_message->set_check_result(its_send_command.get_status());
                    if (_sec_client)
                        its_message->set_sec_client(*_sec_client);
                    its_message->set_env(get_env(_bound_client));

                    if (!is_from_routing) {
                        if (utility::is_notification(its_message->get_message_type())) {
                            if (!is_response_allowed(_bound_client, its_message->get_service(),
                                    its_message->get_instance(), its_message->get_method())) {
                                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                                << " : routing_manager_client::on_message: "
                                                << " received a notification from client 0x" << _bound_client
                                                << " which does not offer service/instance/event "
                                                << its_message->get_service() << "/" << its_message->get_instance()
                                                << "/" << its_message->get_method()
                                                << " ~> Skip message!";
                                return;
                            } else {
                                if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                                        get_sec_client(), its_message->get_service(), its_message->get_instance(),
                                        its_message->get_method())) {
                                    VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                                    << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                                    << " : routing_manager_client::on_message: "
                                                    << " isn't allowed to receive a notification from service/instance/event "
                                                    << its_message->get_service() << "/" << its_message->get_instance()
                                                    << "/" << its_message->get_method()
                                                    << " respectively from client 0x" << _bound_client
                                                    << " ~> Skip message!";
                                    return;
                                }
                                cache_event_payload(its_message);
                            }
                        } else if (utility::is_request(its_message->get_message_type())) {
                            if (configuration_->is_security_enabled()
                                    && configuration_->is_local_routing()
                                    && its_message->get_client() != _bound_client) {
                                VSOMEIP_WARNING << std::hex << "vSomeIP Security: Client 0x"
                                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                                << " received a request from client 0x"
                                                << std::hex << std::setw(4) << std::setfill('0') << its_message->get_client()
                                                << " to service/instance/method " << its_message->get_service()
                                                << "/" << its_message->get_instance() << "/" << its_message->get_method()
                                                << " which doesn't match the bound client 0x"
                                                << std::hex << std::setw(4) << std::setfill('0') << _bound_client
                                                << " ~> skip message!";
                                return;
                            }
                            if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                                    _sec_client, its_message->get_service(), its_message->get_instance(),
                                    its_message->get_method())) {
                                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                                << std::hex << std::setw(4) << std::setfill('0') << its_message->get_client()
                                                << " : routing_manager_client::on_message: "
                                                << "isn't allowed to send a request to service/instance/method "
                                                << its_message->get_service() << "/" << its_message->get_instance()
                                                << "/" << its_message->get_method()
                                                << " ~> Skip message!";
                                return;
                            }
                        } else { // response
                            if (!is_response_allowed(_bound_client, its_message->get_service(),
                                    its_message->get_instance(), its_message->get_method())) {
                                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                                << " : routing_manager_client::on_message: "
                                                << " received a response from client 0x" << _bound_client
                                                << " which does not offer service/instance/method "
                                                << its_message->get_service() << "/" << its_message->get_instance()
                                                << "/" << its_message->get_method()
                                                << " ~> Skip message!";
                                return;
                            } else {
                                if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                                            get_sec_client(), its_message->get_service(), its_message->get_instance(),
                                            its_message->get_method())) {
                                    VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                                    << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                                    << " : routing_manager_client::on_message: "
                                                    << " isn't allowed to receive a response from service/instance/method "
                                                    << its_message->get_service() << "/" << its_message->get_instance()
                                                    << "/" << its_message->get_method()
                                                    << " respectively from client 0x" << _bound_client
                                                    << " ~> Skip message!";
                                    return;
                                }
                            }
                        }
                    } else {
                        if (!configuration_->is_remote_access_allowed()) {
                            // if the message is from routing manager, check if
                            // policy allows remote requests.
                            VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                            << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                            << " : routing_manager_client::on_message: "
                                            << std::hex << "Security: Remote clients via routing manager with client ID 0x" << its_client
                                            << " are not allowed to communicate with service/instance/method "
                                            << its_message->get_service() << "/" << its_message->get_instance()
                                            << "/" << its_message->get_method()
                                            << " respectively with client 0x" << get_client()
                                            << " ~> Skip message!";
                            return;
                        } else if (utility::is_notification(its_message->get_message_type())) {
                            // As subscription is sent on eventgroup level, incoming remote event ID's
                            // need to be checked as well if remote clients are allowed
                            // and the local policy only allows specific events in the eventgroup to be received.
                            if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                                    get_sec_client(), its_message->get_service(), its_message->get_instance(),
                                    its_message->get_method())) {
                                VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << get_client()
                                                << " : routing_manager_client::on_message: "
                                                << " isn't allowed to receive a notification from service/instance/event "
                                                << its_message->get_service() << "/" << its_message->get_instance()
                                                << "/" << its_message->get_method()
                                                << " respectively from remote clients via routing manager with client ID 0x"
                                                << routing_host_id
                                                << " ~> Skip message!";
                                return;
                            }
                            cache_event_payload(its_message);
                        }
                    }
    #ifdef USE_DLT
                    if (client_side_logging_
                        && (client_side_logging_filter_.empty()
                            || (1 == client_side_logging_filter_.count(std::make_tuple(its_message->get_service(), ANY_INSTANCE)))
                            || (1 == client_side_logging_filter_.count(std::make_tuple(its_message->get_service(), its_message->get_instance()))))) {
                        trace::header its_header;
                        if (its_header.prepare(nullptr, false, its_send_command.get_instance())) {
                            uint32_t its_message_size = its_send_command.get_size();
                            if (its_message_size >= uint32_t{vsomeip_v3::protocol::SEND_COMMAND_HEADER_SIZE})
                                its_message_size -= uint32_t{vsomeip_v3::protocol::SEND_COMMAND_HEADER_SIZE};
                            else
                                its_message_size = 0;

                            tc_->trace(its_header.data_, VSOMEIP_TRACE_HEADER_SIZE,
                                    &_data[vsomeip_v3::protocol::SEND_COMMAND_HEADER_SIZE], its_message_size);
                        }
                    }
    #endif

                    host_->on_message(std::move(its_message));
                } else
                    VSOMEIP_ERROR << "Routing proxy: on_message: "
                        << "SomeIP-Header deserialization failed!";
            } else
                VSOMEIP_ERROR << __func__
                    << ": send command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::ASSIGN_CLIENT_ACK_ID:
        {
            client_t its_assigned_client(VSOMEIP_CLIENT_UNSET);
            protocol::assign_client_ack_command its_ack_command;
            its_ack_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK)
                its_assigned_client = its_ack_command.get_assigned();

            on_client_assign_ack(its_assigned_client);
            break;
        }

        case protocol::id_e::ROUTING_INFO_ID:
            if (!configuration_->is_security_enabled() || is_from_routing) {
                on_routing_info(_data, _size);
            } else {
                VSOMEIP_WARNING << "routing_manager_client::on_message: "
                        << "Security: Client 0x"
                        << std::hex << std::setw(4) << std::setfill('0')<< get_client()
                        << " received an routing info from a client which isn't the routing manager"
                        << " : Skip message!";
            }
            break;

        case protocol::id_e::PING_ID:
        {
            protocol::ping_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                send_pong();
                VSOMEIP_TRACE << "PING("
                        << std::hex << std::setw(4) << std::setfill('0') << get_client() << ")";
            } else
                VSOMEIP_ERROR << __func__
                    << ": ping command deserialization failed ("
                    << std::dec << int(its_error) << ")";
            break;
        }

        case protocol::id_e::SUBSCRIBE_ID:
        {
            protocol::subscribe_command its_subscribe_command;
            its_subscribe_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_service = its_subscribe_command.get_service();
                its_instance = its_subscribe_command.get_instance();
                its_eventgroup = its_subscribe_command.get_eventgroup();
                its_major = its_subscribe_command.get_major();
                its_event = its_subscribe_command.get_event();
                its_pending_id = its_subscribe_command.get_pending_id();
                auto its_filter = its_subscribe_command.get_filter();

                std::unique_lock<std::recursive_mutex> its_lock(incoming_subscriptions_mutex_);
                if (its_pending_id != PENDING_SUBSCRIPTION_ID) {
                    its_lock.unlock();
#ifdef VSOMEIP_ENABLE_COMPAT
                    routing_manager_base::set_incoming_subscription_state(its_client, its_service,
                            its_instance, its_eventgroup, its_event, subscription_state_e::IS_SUBSCRIBING);
#endif
                    auto its_info = find_service(its_service, its_instance);
                    if (its_info) {
                        // Remote subscriber: Notify routing manager initially + count subscribes
                        auto self = shared_from_this();
                        host_->on_subscription(
                                its_service, its_instance, its_eventgroup, its_client, _sec_client,
                                get_env(its_client), true,
                                [this, self, its_client, its_service, its_instance, its_eventgroup,
                                 its_event, its_filter, its_pending_id,
                                 its_major](const bool _subscription_accepted) {
                                    std::uint32_t its_count(0);
                                    if (_subscription_accepted) {
                                        send_subscribe_ack(its_client, its_service, its_instance,
                                                           its_eventgroup, its_event,
                                                           its_pending_id);
                                        std::set<event_t> its_already_subscribed_events;
                                        bool inserted = insert_subscription(
                                                its_service, its_instance, its_eventgroup,
                                                its_event, its_filter, VSOMEIP_ROUTING_CLIENT,
                                                &its_already_subscribed_events);
                                        if (inserted) {
                                            notify_remote_initially(its_service, its_instance,
                                                                    its_eventgroup,
                                                                    its_already_subscribed_events);
                                        }
#ifdef VSOMEIP_ENABLE_COMPAT
                                        send_pending_notify_ones(its_service, its_instance,
                                                                 its_eventgroup, its_client, true);
#endif
                                        its_count = get_remote_subscriber_count(
                                                its_service, its_instance, its_eventgroup, true);
                                    } else {
                                        send_subscribe_nack(its_client, its_service, its_instance,
                                                            its_eventgroup, its_event,
                                                            its_pending_id);
                                    }
                                    VSOMEIP_INFO
                                            << "SUBSCRIBE(" << std::hex << std::setw(4)
                                            << std::setfill('0') << its_client << "): [" << std::hex
                                            << std::setw(4) << std::setfill('0') << its_service
                                            << "." << std::hex << std::setw(4) << std::setfill('0')
                                            << its_instance << "." << std::hex << std::setw(4)
                                            << std::setfill('0') << its_eventgroup << ":"
                                            << std::hex << std::setw(4) << std::setfill('0')
                                            << its_event << ":" << std::dec << (uint16_t)its_major
                                            << "] " << std::boolalpha
                                            << (its_pending_id != PENDING_SUBSCRIPTION_ID) << " "
                                            << (_subscription_accepted
                                                        ? std::to_string(its_count) + " accepted."
                                                        : "not accepted.");
                                });
                    } else {
                        send_subscribe_nack(its_client, its_service, its_instance, its_eventgroup,
                                            its_event, its_pending_id);
                    }
#ifdef VSOMEIP_ENABLE_COMPAT
                    routing_manager_base::erase_incoming_subscription_state(
                            its_client, its_service, its_instance, its_eventgroup, its_event);
#endif
                } else if (is_client_known(its_client)) {
                    its_lock.unlock();
                    if (!is_from_routing) {
                        if (its_event == ANY_EVENT) {
                           if (!is_subscribe_to_any_event_allowed(_sec_client, its_client, its_service, its_instance, its_eventgroup)) {
                               VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                                       << " : routing_manager_client::on_message: "
                                       << " isn't allowed to subscribe to service/instance/event "
                                       << its_service << "/" << its_instance << "/ANY_EVENT"
                                       << " which violates the security policy ~> Skip subscribe!";
                               return;
                           }
                        } else {
                            if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                                    _sec_client, its_service, its_instance, its_event)) {
                                VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                                        << " : routing_manager_client::on_message: "
                                        << " subscribes to service/instance/event "
                                        << its_service << "/" << its_instance << "/" << its_event
                                        << " which violates the security policy ~> Skip subscribe!";
                                return;
                            }
                        }
                    } else {
                        if (!configuration_->is_remote_access_allowed()) {
                            VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                                    << " : routing_manager_client::on_message: "
                                    << std::hex << "Routing manager with client ID 0x"
                                    << its_client
                                    << " isn't allowed to subscribe to service/instance/event "
                                    << its_service << "/" << its_instance
                                    << "/" << its_event
                                    << " respectively to client 0x" << get_client()
                                    << " ~> Skip Subscribe!";
                            return;
                        }
                    }

                    // Local & already known subscriber: create endpoint + send (N)ACK + insert subscription
#ifdef VSOMEIP_ENABLE_COMPAT
                    routing_manager_base::set_incoming_subscription_state(its_client, its_service,
                            its_instance, its_eventgroup, its_event, subscription_state_e::IS_SUBSCRIBING);
#endif
                    (void) ep_mgr_->find_or_create_local(its_client);
                    auto self = shared_from_this();
                    auto its_env = get_env(its_client);

                    auto its_info = find_service(its_service, its_instance);
                    if (its_info) {
                        host_->on_subscription(
                                its_service, its_instance, its_eventgroup, its_client, _sec_client,
                                its_env, true,
                                [this, self, its_client, its_filter, _sec_client, its_env,
                                 its_service, its_instance, its_eventgroup, its_event,
                                 its_major](const bool _subscription_accepted) {
                                    if (!_subscription_accepted) {
                                        send_subscribe_nack(its_client, its_service, its_instance,
                                                            its_eventgroup, its_event,
                                                            PENDING_SUBSCRIPTION_ID);
                                    } else {
                                        send_subscribe_ack(its_client, its_service, its_instance,
                                                           its_eventgroup, its_event,
                                                           PENDING_SUBSCRIPTION_ID);
                                        routing_manager_base::subscribe(
                                                its_client, _sec_client, its_service, its_instance,
                                                its_eventgroup, its_major, its_event, its_filter);
#ifdef VSOMEIP_ENABLE_COMPAT
                                        send_pending_notify_ones(its_service, its_instance,
                                                                 its_eventgroup, its_client);
#endif
                                    }
                                });
                    } else {
                        send_subscribe_nack(its_client, its_service, its_instance, its_eventgroup,
                                            its_event, PENDING_SUBSCRIPTION_ID);
                    }
#ifdef VSOMEIP_ENABLE_COMPAT
                    routing_manager_base::erase_incoming_subscription_state(
                            its_client, its_service, its_instance, its_eventgroup, its_event);
#endif
                } else {
                    if (_sec_client) {
                        // Local & not yet known subscriber ~> set pending until subscriber gets known!
                        subscription_data_t subscription = {
                                its_service, its_instance,
                                its_eventgroup, its_major,
                                its_event, its_filter,
                                *_sec_client
                        };
                        pending_incoming_subscriptions_[its_client].insert(subscription);
                    } else {
                        VSOMEIP_WARNING << __func__
                                << ": Local subscription without security info.";
                    }
                }

                if (its_pending_id == PENDING_SUBSCRIPTION_ID) { // local subscription
                    VSOMEIP_INFO << "SUBSCRIBE("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << its_client << "): ["
                        << std::setw(4) << its_service << "."
                        << std::setw(4) << its_instance << "."
                        << std::setw(4) << its_eventgroup << ":"
                        << std::setw(4) << its_event << ":"
                        << std::dec << (uint16_t)its_major << "]";
                }
            } else {
                VSOMEIP_ERROR << __func__
                    << ": subscribe command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            }
            break;
        }

        case protocol::id_e::UNSUBSCRIBE_ID:
        {
            protocol::unsubscribe_command its_unsubscribe;
            its_unsubscribe.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_unsubscribe.get_client();
                its_service = its_unsubscribe.get_service();
                its_instance = its_unsubscribe.get_instance();
                its_eventgroup = its_unsubscribe.get_eventgroup();
                its_event = its_unsubscribe.get_event();
                its_pending_id = its_unsubscribe.get_pending_id();

                host_->on_subscription(its_service, its_instance, its_eventgroup,
                        its_client, _sec_client, get_env(its_client), false,
                        [](const bool _subscription_accepted){
                            (void)_subscription_accepted;
                        }
                );
                if (its_pending_id == PENDING_SUBSCRIPTION_ID) {
                    // Local subscriber: withdraw subscription
                    routing_manager_base::unsubscribe(its_client, _sec_client, its_service, its_instance, its_eventgroup, its_event);
                } else {
                    // Remote subscriber: withdraw subscription only if no more remote subscriber exists
                    its_remote_subscriber_count = get_remote_subscriber_count(its_service,
                            its_instance, its_eventgroup, false);
                    if (!its_remote_subscriber_count) {
                        routing_manager_base::unsubscribe(VSOMEIP_ROUTING_CLIENT, nullptr, its_service,
                                its_instance, its_eventgroup, its_event);
                    }
                    send_unsubscribe_ack(its_service, its_instance, its_eventgroup, its_pending_id);
                }
                VSOMEIP_INFO << "UNSUBSCRIBE("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "."
                    << std::setw(4) << its_event << "] "
                    << (bool)(its_pending_id != PENDING_SUBSCRIPTION_ID) << " "
                    << std::dec << its_remote_subscriber_count;
            } else
                VSOMEIP_ERROR << __func__
                    << ": unsubscribe command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::EXPIRE_ID:
        {
            protocol::expire_command its_expire;
            its_expire.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_expire.get_client();
                its_service = its_expire.get_service();
                its_instance = its_expire.get_instance();
                its_eventgroup = its_expire.get_eventgroup();
                its_event = its_expire.get_event();
                its_pending_id = its_expire.get_pending_id();

                host_->on_subscription(its_service, its_instance, its_eventgroup, its_client,
                        _sec_client, get_env(its_client), false,
                        [](const bool _subscription_accepted){ (void)_subscription_accepted; });
                if (its_pending_id == PENDING_SUBSCRIPTION_ID) {
                    // Local subscriber: withdraw subscription
                    routing_manager_base::unsubscribe(its_client, _sec_client,
                            its_service, its_instance, its_eventgroup, its_event);
                } else {
                    // Remote subscriber: withdraw subscription only if no more remote subscriber exists
                    its_remote_subscriber_count = get_remote_subscriber_count(its_service,
                            its_instance, its_eventgroup, false);
                    if (!its_remote_subscriber_count) {
                        routing_manager_base::unsubscribe(VSOMEIP_ROUTING_CLIENT, nullptr,
                                its_service, its_instance, its_eventgroup, its_event);
                    }
                }
                VSOMEIP_INFO << "EXPIRED SUBSCRIPTION("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "."
                    << std::setw(4) << its_event << "] "
                    << (bool)(its_pending_id != PENDING_SUBSCRIPTION_ID) << " "
                    << std::dec << its_remote_subscriber_count;
            } else
                VSOMEIP_ERROR << __func__
                    << ": expire deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::SUBSCRIBE_NACK_ID:
        {
            protocol::subscribe_nack_command its_subscribe_nack;
            its_subscribe_nack.deserialize(its_buffer,  its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_service = its_subscribe_nack.get_service();
                its_instance = its_subscribe_nack.get_instance();
                its_eventgroup = its_subscribe_nack.get_eventgroup();
                its_subscriber = its_subscribe_nack.get_subscriber();
                its_event = its_subscribe_nack.get_event();

                on_subscribe_nack(its_subscriber, its_service, its_instance, its_eventgroup, its_event);
                VSOMEIP_INFO << "SUBSCRIBE NACK("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "."
                    << std::setw(4) << its_event << "]";
            } else
                VSOMEIP_ERROR << __func__
                    << ": subscribe nack command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::SUBSCRIBE_ACK_ID:
        {
            protocol::subscribe_ack_command its_subscribe_ack;
            its_subscribe_ack.deserialize(its_buffer,  its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_service = its_subscribe_ack.get_service();
                its_instance = its_subscribe_ack.get_instance();
                its_eventgroup = its_subscribe_ack.get_eventgroup();
                its_subscriber = its_subscribe_ack.get_subscriber();
                its_event = its_subscribe_ack.get_event();

                on_subscribe_ack(its_subscriber, its_service, its_instance, its_eventgroup, its_event);
                VSOMEIP_INFO << "SUBSCRIBE ACK("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "."
                    << std::setw(4) << its_event << "]";
            } else
                VSOMEIP_ERROR << __func__
                    << ": subscribe ack command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::OFFERED_SERVICES_RESPONSE_ID:
        {
            protocol::offered_services_response_command its_response;
            its_response.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                if (!configuration_->is_security_enabled() || is_from_routing) {
                    on_offered_services_info(its_response);
                } else {
                    VSOMEIP_WARNING << std::hex << "Security: Client 0x" << get_client()
                        << " received an offered services info from a client which isn't the routing manager"
                        << " : Skip message!";
                }
            } else
                VSOMEIP_ERROR << __func__
                    << ": offered services response command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }
        case protocol::id_e::RESEND_PROVIDED_EVENTS_ID:
        {
            protocol::resend_provided_events_command its_command;
            its_command.deserialize(its_buffer,  its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                resend_provided_event_registrations();
                send_resend_provided_event_response(its_command.get_remote_offer_id());

                VSOMEIP_INFO << "RESEND_PROVIDED_EVENTS("
                        << std::hex << std::setw(4) << std::setfill('0')
                        << its_command.get_client() << ")";
            } else
                VSOMEIP_ERROR << __func__
                    << ": resend provided events command deserialization failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }
        case protocol::id_e::SUSPEND_ID:
        {
            on_suspend(); // cleanup remote subscribers
            break;
        }
#ifndef VSOMEIP_DISABLE_SECURITY
        case protocol::id_e::UPDATE_SECURITY_POLICY_INT_ID:
            is_internal_policy_update = true;
            [[gnu::fallthrough]];
        case protocol::id_e::UPDATE_SECURITY_POLICY_ID:
        {
            if (!configuration_->is_security_enabled() || is_from_routing) {
                protocol::update_security_policy_command its_command(is_internal_policy_update);
                its_command.deserialize(its_buffer, its_error);
                if (its_error == protocol::error_e::ERROR_OK) {
                    auto its_policy = its_command.get_policy();
                    uid_t its_uid;
                    gid_t its_gid;
                    if (its_policy->get_uid_gid(its_uid, its_gid)) {
                        if (is_internal_policy_update
                                || its_policy_manager->is_policy_update_allowed(its_uid, its_policy)) {
                            its_policy_manager->update_security_policy(its_uid, its_gid, its_policy);
                            send_update_security_policy_response(its_command.get_update_id());
                        }
                    } else {
                        VSOMEIP_ERROR << "vSomeIP Security: Policy has no valid uid/gid!";
                    }
                } else {
                    VSOMEIP_ERROR << "vSomeIP Security: Policy deserialization failed!";
                }
            } else {
                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " : routing_manager_client::on_message: "
                                << " received a security policy update from a client which isn't the routing manager"
                                << " : Skip message!";
            }
            break;
        }

        case protocol::id_e::REMOVE_SECURITY_POLICY_ID:
        {
            if (!configuration_->is_security_enabled() || is_from_routing) {
                protocol::remove_security_policy_command its_command;
                its_command.deserialize(its_buffer, its_error);
                if (its_error == protocol::error_e::ERROR_OK) {

                    uid_t its_uid(its_command.get_uid());
                    gid_t its_gid(its_command.get_gid());

                    if (its_policy_manager->is_policy_removal_allowed(its_uid)) {
                        its_policy_manager->remove_security_policy(its_uid, its_gid);
                        send_remove_security_policy_response(its_command.get_update_id());
                    }
                } else
                    VSOMEIP_ERROR << __func__
                        << ": remove security policy command deserialization failed ("
                        << static_cast<int>(its_error)
                        << ")";
            } else
                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " : routing_manager_client::on_message: "
                                << "received a security policy removal from a client which isn't the routing manager"
                                << " : Skip message!";
            break;
        }

        case protocol::id_e::DISTRIBUTE_SECURITY_POLICIES_ID:
        {
            if (!configuration_->is_security_enabled() || is_from_routing) {
                protocol::distribute_security_policies_command its_command;
                its_command.deserialize(its_buffer, its_error);
                if (its_error == protocol::error_e::ERROR_OK) {
                    for (auto p : its_command.get_policies()) {
                        uid_t its_uid;
                        gid_t its_gid;
                        p->get_uid_gid(its_uid, its_gid);
                        if (its_policy_manager->is_policy_update_allowed(its_uid, p))
                            its_policy_manager->update_security_policy(its_uid, its_gid, p);
                    }
                } else
                    VSOMEIP_ERROR << __func__
                        << ": distribute security policies command deserialization failed ("
                        << static_cast<int>(its_error)
                        << ")";
            } else
                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " : routing_manager_client::on_message: "
                                << " received a security policy distribution command from a client which isn't the routing manager"
                                << " : Skip message!";
            break;
        }

        case protocol::id_e::UPDATE_SECURITY_CREDENTIALS_ID:
        {
            if (!configuration_->is_security_enabled() || is_from_routing) {
                protocol::update_security_credentials_command its_command;
                its_command.deserialize(its_buffer, its_error);
                if (its_error == protocol::error_e::ERROR_OK) {
                    on_update_security_credentials(its_command);
                } else
                    VSOMEIP_ERROR << __func__
                        << ": update security credentials command deserialization failed ("
                        << static_cast<int>(its_error)
                        << ")";
            } else
                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                                << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " : routing_manager_client::on_message: "
                                << "received a security credential update from a client which isn't the routing manager"
                                << " : Skip message!";

            break;
        }
#endif // !VSOMEIP_DISABLE_SECURITY
        case protocol::id_e::CONFIG_ID: {
            protocol::config_command its_command;
            protocol::error_e its_command_error;
            its_command.deserialize(its_buffer, its_command_error);
            if (its_command_error != protocol::error_e::ERROR_OK) {
                VSOMEIP_ERROR << __func__ << ": config command deserialization failed (" << std::dec
                              << static_cast<int>(its_command_error) << ")";
                break;
            }
            if (its_command.contains("hostname")) {
                add_known_client(its_command.get_client(), its_command.at("hostname"));
            }
            break;
        }
        default:
            break;
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": dummy command deserialization failed ("
            << std::dec << static_cast<int>(its_error)
            << ")";
}

void routing_manager_client::on_routing_info(
        const byte_t *_data, uint32_t _size) {
#if 0
    std::stringstream msg;
    msg << "rmp::on_routing_info(" << std::hex << std::setw(4) << std::setfill('0') << get_client() << "): ";
    for (uint32_t i = 0; i < _size; ++i)
        msg << std::hex << std::setw(2) << std::setfill('0') << (int)_data[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif
    auto its_policy_manager = configuration_->get_policy_manager();
    if (!its_policy_manager)
        return;

    std::vector<byte_t> its_buffer(_data, _data + _size);
    protocol::error_e its_error;

    protocol::routing_info_command its_command;
    its_command.deserialize(its_buffer, its_error);
    if (its_error != protocol::error_e::ERROR_OK) {
        VSOMEIP_ERROR << __func__
                << ": deserializing routing info command failed ("
                << static_cast<int>(its_error)
                << ")";
        return;
    }

    for (const auto &e : its_command.get_entries()) {
        auto its_client = e.get_client();
        switch (e.get_type()) {
            case protocol::routing_info_entry_type_e::RIE_ADD_CLIENT:
            {
                auto its_address = e.get_address();
                if (!its_address.is_unspecified()) {
                    add_guest(its_client, its_address, e.get_port());
                    add_known_client(its_client, "");
                }

                if (its_client == get_client()) {
                    VSOMEIP_INFO << "Application/Client "
                                 << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                 << " (" << host_->get_name() << ") is registered.";
#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
                    if (!its_policy_manager->check_credentials(get_client(), get_sec_client())) {
                        VSOMEIP_ERROR << "vSomeIP Security: Client 0x" << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " : routing_manager_client::on_routing_info: RIE_ADD_CLIENT: isn't allowed"
                                << " to use the server endpoint due to credential check failed!";
                        deregister_application();
                        host_->on_state(static_cast<state_type_e>(inner_state_type_e::ST_DEREGISTERED));
                        return;
                    }
#endif
                    {
                        std::lock_guard<std::mutex> its_lock(state_mutex_);
                        if (state_ == inner_state_type_e::ST_REGISTERING) {
                            boost::system::error_code ec;
                            register_application_timer_.cancel(ec);
                            send_registered_ack();
                            send_pending_commands();
                            state_ = inner_state_type_e::ST_REGISTERED;
                            // Notify stop() call about clean deregistration
                            state_condition_.notify_one();
                        }
                    }

                    // inform host about its own registration state changes
                    if (state_ == inner_state_type_e::ST_REGISTERED) {
                        host_->on_state(static_cast<state_type_e>(inner_state_type_e::ST_REGISTERED));
                    }
                }
                break;
            }

            case protocol::routing_info_entry_type_e::RIE_DELETE_CLIENT:
            {
                {
                    std::lock_guard<std::mutex> its_lock(known_clients_mutex_);
                    known_clients_.erase(its_client);
                }
                if (its_client == get_client()) {
                    its_policy_manager->remove_client_to_sec_client_mapping(its_client);
                    VSOMEIP_INFO << "Application/Client " << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                << " (" << host_->get_name() << ") is deregistered.";

                    // inform host about its own registration state changes
                    host_->on_state(static_cast<state_type_e>(inner_state_type_e::ST_DEREGISTERED));

                    {
                        std::lock_guard<std::mutex> its_lock(state_mutex_);
                        state_ = inner_state_type_e::ST_DEREGISTERED;
                        // Notify stop() call about clean deregistration
                        state_condition_.notify_one();
                    }
                } else if (its_client != VSOMEIP_ROUTING_CLIENT) {
                    remove_local(its_client, true);
                }
                break;
            }

            case protocol::routing_info_entry_type_e::RIE_ADD_SERVICE_INSTANCE:
            {
                auto its_address = e.get_address();
                if (!its_address.is_unspecified()) {
                    add_guest(its_client, its_address, e.get_port());
                    add_known_client(its_client, "");
                }
                {
                    // Add yet unknown clients that offer services. Otherwise,
                    // the service cannot be used. The entry will be overwritten,
                    // when the offering clients connects.
                    std::lock_guard<std::mutex> its_lock(known_clients_mutex_);
                    if (known_clients_.find(its_client) == known_clients_.end()) {
                        known_clients_[its_client] = "";
                    }
                }

                for (const auto &s : e.get_services()) {

                    const auto its_service(s.service_);
                    const auto its_instance(s.instance_);
                    const auto its_major(s.major_);
                    const auto its_minor(s.minor_);

                    {
                        std::lock_guard<std::mutex> its_lock(local_services_mutex_);

                        // Check whether the service instance is already known. If yes,
                        // continue with the next service within the routing info.
                        auto found_service = local_services_.find(its_service);
                        if (found_service != local_services_.end()) {
                            if (found_service->second.find(its_instance) != found_service->second.end())
                                continue;
                        }

                        local_services_[its_service][its_instance]
                            = std::make_tuple(its_major, its_minor, its_client);
                    }
                    {
                        std::lock_guard<std::mutex> its_lock(state_mutex_);
                        send_pending_subscriptions(its_service, its_instance, its_major);
                    }
                    host_->on_availability(its_service, its_instance,
                            availability_state_e::AS_AVAILABLE, its_major, its_minor);
                    VSOMEIP_INFO << "ON_AVAILABLE("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << get_client() << "): ["
                        << std::setw(4) << its_service << "."
                        << std::setw(4) << its_instance
                        << ":" << std::dec << int(its_major) << "." << std::dec << its_minor << "]";
                }
                break;
            }

            case protocol::routing_info_entry_type_e::RIE_DELETE_SERVICE_INSTANCE:
            {
                for (const auto &s : e.get_services()) {
                    const auto its_service(s.service_);
                    const auto its_instance(s.instance_);
                    const auto its_major(s.major_);
                    const auto its_minor(s.minor_);

                    {
                        std::lock_guard<std::mutex> its_lock(local_services_mutex_);
                        auto found_service = local_services_.find(its_service);
                        if (found_service != local_services_.end()) {
                            found_service->second.erase(its_instance);
                            // move previously offering client to history
                            local_services_history_[its_service][its_instance].insert(its_client);
                            if (found_service->second.size() == 0) {
                                local_services_.erase(its_service);
                            }
                        }
                    }
                    on_stop_offer_service(its_service, its_instance, its_major, its_minor);
                    host_->on_availability(its_service, its_instance,
                            availability_state_e::AS_UNAVAILABLE, its_major, its_minor);
                    VSOMEIP_INFO << "ON_UNAVAILABLE("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << get_client() << "): ["
                        << std::setw(4) << its_service << "."
                        << std::setw(4) << its_instance
                        << ":" << std::dec << int(its_major) << "." << std::dec << its_minor << "]";
                }
                break;
            }

            default:
                VSOMEIP_ERROR << __func__
                    << ": Unknown routing info entry type ("
                    << static_cast<int>(e.get_type())
                    << ")";
                break;
        }
    }

    {
        struct subscription_info {
            service_t service_id_;
            instance_t instance_id_;
            eventgroup_t eventgroup_id_;
            client_t client_id_;
            major_version_t major_;
            event_t event_;
            std::shared_ptr<debounce_filter_impl_t> filter_;
            vsomeip_sec_client_t sec_client_;
            std::string env_;
        };
        std::lock_guard<std::recursive_mutex> its_lock(incoming_subscriptions_mutex_);
        std::forward_list<struct subscription_info> subscription_actions;
        if (pending_incoming_subscriptions_.size()) {
            {
                std::lock_guard<std::mutex> its_lock(known_clients_mutex_);
                for (const auto &k : known_clients_) {
                    auto its_client = pending_incoming_subscriptions_.find(k.first);
                    if (its_client != pending_incoming_subscriptions_.end()) {
                        for (const auto &subscription : its_client->second) {
                            subscription_actions.push_front(
                                { subscription.service_, subscription.instance_,
                                  subscription.eventgroup_, k.first,
                                  subscription.major_, subscription.event_,
                                  subscription.filter_,
                                  subscription.sec_client_,
                                  get_env_unlocked(k.first)});
                        }
                    }
                }
            }
            for (const subscription_info &si : subscription_actions) {
#ifdef VSOMEIP_ENABLE_COMPAT
                routing_manager_base::set_incoming_subscription_state(si.client_id_, si.service_id_, si.instance_id_,
                        si.eventgroup_id_, si.event_, subscription_state_e::IS_SUBSCRIBING);
#endif
                (void) ep_mgr_->find_or_create_local(si.client_id_);
                auto self = shared_from_this();
                host_->on_subscription(
                        si.service_id_, si.instance_id_, si.eventgroup_id_,
                        si.client_id_, &si.sec_client_, si.env_, true,
                        [this, self, si](const bool _subscription_accepted) {
                    if (!_subscription_accepted) {
                        send_subscribe_nack(si.client_id_, si.service_id_,
                                si.instance_id_, si.eventgroup_id_, si.event_, PENDING_SUBSCRIPTION_ID);
                    } else {
                        send_subscribe_ack(si.client_id_, si.service_id_,
                                si.instance_id_, si.eventgroup_id_, si.event_, PENDING_SUBSCRIPTION_ID);
                        routing_manager_base::subscribe(si.client_id_, &si.sec_client_,
                                si.service_id_, si.instance_id_, si.eventgroup_id_,
                                si.major_, si.event_, si.filter_);
#ifdef VSOMEIP_ENABLE_COMPAT
                        send_pending_notify_ones(si.service_id_,
                                si.instance_id_, si.eventgroup_id_, si.client_id_);
#endif
                    }
#ifdef VSOMEIP_ENABLE_COMPAT
                    routing_manager_base::erase_incoming_subscription_state(si.client_id_, si.service_id_,
                            si.instance_id_, si.eventgroup_id_, si.event_);
#endif
                    {
                        std::lock_guard<std::recursive_mutex> its_lock2(incoming_subscriptions_mutex_);
                        pending_incoming_subscriptions_.erase(si.client_id_);
                    }
                });
            }
        }
    }
}

void routing_manager_client::on_offered_services_info(
        protocol::offered_services_response_command &_command) {

    std::vector<std::pair<service_t, instance_t>> its_offered_services_info;

    for (const auto &s : _command.get_services())
        its_offered_services_info.push_back(std::make_pair(s.service_, s.instance_));

    host_->on_offered_services_info(its_offered_services_info);
}

void routing_manager_client::reconnect(const std::map<client_t, std::string> &_clients) {
    auto its_policy_manager = configuration_->get_policy_manager();
    if (!its_policy_manager)
        return;

    // inform host about its own registration state changes
    host_->on_state(static_cast<state_type_e>(inner_state_type_e::ST_DEREGISTERED));

    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        state_ = inner_state_type_e::ST_DEREGISTERED;
        // Notify stop() call about clean deregistration
        state_condition_.notify_one();
    }


    // Remove all local connections/endpoints
    for (const auto &c : _clients) {
        if (c.first != VSOMEIP_ROUTING_CLIENT) {
            remove_local(c.first, true);
        }
    }

    VSOMEIP_INFO << std::hex << "Application/Client "
                 << std::hex << std::setw(4) << std::setfill('0') << get_client()
                 <<": Reconnecting to routing manager.";

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    if (!its_policy_manager->check_credentials(get_client(), get_sec_client())) {
        VSOMEIP_ERROR << "vSomeIP Security: Client 0x" << std::hex << std::setw(4) << std::setfill('0') << get_client()
                << " :  routing_manager_client::reconnect: isn't allowed"
                << " to use the server endpoint due to credential check failed!";
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->stop();
        }
        return;
    }
#endif

    std::lock_guard<std::mutex> its_lock(sender_mutex_);
    if (sender_) {
        sender_->restart();
    }
}

void routing_manager_client::assign_client() {

    VSOMEIP_INFO << __func__ << ": (" << std::hex << std::setw(4) << std::setfill('0')
                 << get_client() << ":" << host_->get_name() << ")";

    protocol::assign_client_command its_command;
    its_command.set_client(get_client());
    its_command.set_name(host_->get_name());

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error != protocol::error_e::ERROR_OK) {

        VSOMEIP_ERROR << __func__ << ": command creation failed ("
                << std::dec << static_cast<int>(its_error) << ")";
        return;
    }

    std::lock_guard<std::mutex> its_state_lock(state_mutex_);
    if (is_connected_) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            if (state_ != inner_state_type_e::ST_DEREGISTERED) {
                VSOMEIP_WARNING << __func__ << ": (" << std::hex << std::setw(4) << std::setfill('0')
                                << get_client() << ") Non-Deregistered State Set. Returning";
                return;
            }
            state_ = inner_state_type_e::ST_ASSIGNING;

            sender_->send(&its_buffer[0], static_cast<uint32_t>(its_buffer.size()));

            boost::system::error_code ec;
            register_application_timer_.cancel(ec);
            register_application_timer_.expires_from_now(std::chrono::milliseconds(3000));
            register_application_timer_.async_wait(
                    std::bind(
                            &routing_manager_client::assign_client_timeout_cbk,
                            std::dynamic_pointer_cast<routing_manager_client>(shared_from_this()),
                            std::placeholders::_1));
        } else {
            VSOMEIP_WARNING << __func__ << ": (" << std::hex << std::setw(4) << std::setfill('0')
                            << get_client() << ") sender not initialized. Ignoring client assignment";
        }
    }
    else {
        VSOMEIP_WARNING << __func__ << ": (" << std::hex << std::setw(4) << std::setfill('0')
                        << get_client() << ") not connected. Ignoring client assignment";
    }
}

void routing_manager_client::register_application() {

    if (!receiver_) {
        VSOMEIP_ERROR << __func__
                << "Cannot register. Local server endpoint does not exist.";
        return;
    }

    auto its_configuration(get_configuration());
    if (its_configuration->is_local_routing()) {
        VSOMEIP_INFO << "Registering to routing manager @ "
                << its_configuration->get_network() << "-0";
    } else {
        auto its_routing_address(its_configuration->get_routing_host_address());
        auto its_routing_port(its_configuration->get_routing_host_port());
        VSOMEIP_INFO << "Registering to routing manager @ "
                << its_routing_address.to_string() << ":" << its_routing_port;
    }

    protocol::register_application_command its_command;
    its_command.set_client(get_client());
    its_command.set_port(receiver_->get_local_port());

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        if (is_connected_) {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                state_ = inner_state_type_e::ST_REGISTERING;
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));

                register_application_timer_.cancel();
                register_application_timer_.expires_from_now(std::chrono::milliseconds(3000));
                register_application_timer_.async_wait(
                        std::bind(
                                &routing_manager_client::register_application_timeout_cbk,
                                std::dynamic_pointer_cast<routing_manager_client>(shared_from_this()),
                                std::placeholders::_1));

                // Send a `config_command` to share our hostname with the other application.
                protocol::config_command its_command_config;
                its_command_config.set_client(get_client());
                its_command_config.insert("hostname", get_client_host());

                std::vector<byte_t> its_buffer_config;
                its_command_config.serialize(its_buffer_config, its_error);

                if (its_error == protocol::error_e::ERROR_OK) {
                    sender_->send(&its_buffer_config[0],
                                  static_cast<uint32_t>(its_buffer_config.size()));
                } else {
                    VSOMEIP_ERROR << __func__ << ": config command serialization failed("
                                  << std::dec << int(its_error) << ")";
                }
            }
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": register application command serialization failed("
                      << std::dec << int(its_error) << ")";
    }
}

void routing_manager_client::deregister_application() {

    protocol::deregister_application_command its_command;
    its_command.set_client(get_client());

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        if (is_connected_)
        {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
            }
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": deregister application command serialization failed("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::send_pong() const {

    protocol::pong_command its_command;
    its_command.set_client(get_client());

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        if (is_connected_) {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
            }
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": pong command serialization failed("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::send_request_services(const std::set<protocol::service> &_requests) {

    if (!_requests.size()) {
        return;
    }

    protocol::request_service_command its_command;
    its_command.set_client(get_client());
    its_command.set_services(_requests);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);
    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else {
        VSOMEIP_ERROR << __func__ << ": request service serialization failed ("
                << std::dec << static_cast<int>(its_error) << ")";
    }
}

void routing_manager_client::send_release_service(client_t _client, service_t _service,
        instance_t _instance) {

    (void)_client;

    protocol::release_service_command its_command;
    its_command.set_client(get_client());
    its_command.set_service(_service);
    its_command.set_instance(_instance);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);
    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    }
}

void routing_manager_client::send_pending_event_registrations(client_t _client) {

    protocol::register_events_command its_command;
    its_command.set_client(_client);
    std::set<vsomeip_v3::routing_manager_client::event_data_t>::iterator it = pending_event_registrations_.begin();

    while(it != pending_event_registrations_.end())
    {
        for(; it!=pending_event_registrations_.end(); it++) {
            protocol::register_event reg(it->service_, it->instance_, it->notifier_, it->type_,
                                it->is_provided_, it->reliability_, it->is_cyclic_
                                , (uint16_t)it->eventgroups_.size(), it->eventgroups_);
            if(!its_command.add_registration(reg)) {break;}
        }

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            if (sender_) {
                sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
            }
        } else
            VSOMEIP_ERROR << __func__
                << ": register event command serialization failed ("
                << std::dec << int(its_error) << ")";
    }
}

void routing_manager_client::send_register_event(client_t _client,
        service_t _service, instance_t _instance,
        event_t _notifier,
        const std::set<eventgroup_t> &_eventgroups, const event_type_e _type,
        reliability_type_e _reliability,
        bool _is_provided, bool _is_cyclic) {

    (void)_client;

    protocol::register_events_command its_command;
    its_command.set_client(get_client());

    protocol::register_event reg(_service, _instance, _notifier, _type,
                                _is_provided, _reliability, _is_cyclic,
                                (uint16_t)_eventgroups.size(), _eventgroups);

    if(!its_command.add_registration(reg)) {
        VSOMEIP_ERROR << __func__ << ": register event command is too long.";
    }

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }

        if (_is_provided) {
            VSOMEIP_INFO << "REGISTER EVENT("
                << std::hex << std::setfill('0')
                << std::setw(4) << get_client() << "): ["
                << std::setw(4) << _service << "."
                << std::setw(4) << _instance << "."
                << std::setw(4) << _notifier
                << ":is_provider=" << std::boolalpha << _is_provided << "]";
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": register event command serialization failed ("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::on_subscribe_ack(client_t _client,
        service_t _service, instance_t _instance, eventgroup_t _eventgroup, event_t _event) {
    (void)_client;
#if 0
    VSOMEIP_ERROR << "routing_manager_client::" << __func__
            << "(" << std::hex << std::setw(4) << std::setfill('0') << host_->get_client() << "):"
            << "event="
            << std::hex << std::setw(4) << std::setfill('0') << _service << "."
            << std::hex << std::setw(4) << std::setfill('0') << _instance << "."
            << std::hex << std::setw(4) << std::setfill('0') << _eventgroup << "."
            << std::hex << std::setw(4) << std::setfill('0') << _event;
#endif
    if (_event == ANY_EVENT) {
        auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
        if (its_eventgroup) {
            for (const auto& its_event : its_eventgroup->get_events()) {
                host_->on_subscription_status(_service, _instance, _eventgroup, its_event->get_event(), 0x0 /*OK*/);
            }
        }
    } else {
        host_->on_subscription_status(_service, _instance, _eventgroup, _event, 0x0 /*OK*/);
    }
}

void routing_manager_client::on_subscribe_nack(client_t _client,
        service_t _service, instance_t _instance, eventgroup_t _eventgroup, event_t _event) {
    (void)_client;
    if (_event == ANY_EVENT) {
        auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
        if (its_eventgroup) {
            for (const auto& its_event : its_eventgroup->get_events()) {
                host_->on_subscription_status(_service, _instance, _eventgroup, its_event->get_event(), 0x7 /*Rejected*/);
            }
        }
    } else {
        host_->on_subscription_status(_service, _instance, _eventgroup, _event, 0x7 /*Rejected*/);
    }
}

void routing_manager_client::cache_event_payload(
        const std::shared_ptr<message> &_message) {
    const service_t its_service(_message->get_service());
    const instance_t its_instance(_message->get_instance());
    const method_t its_method(_message->get_method());
    std::shared_ptr<event> its_event = find_event(its_service, its_instance, its_method);
    if (its_event) {
        if (its_event->is_field()) {
            its_event->prepare_update_payload(_message->get_payload(), true);
            its_event->update_payload();
        }
    } else {
        // we received a event which was not yet requested
        std::set<eventgroup_t> its_eventgroups;
        // create a placeholder field until someone requests this event with
        // full information like eventgroup, field or not etc.
        routing_manager_base::register_event(host_->get_client(),
                its_service, its_instance,
                its_method,
                its_eventgroups, event_type_e::ET_UNKNOWN,
                reliability_type_e::RT_UNKNOWN,
                std::chrono::milliseconds::zero(), false, true,
                nullptr,
                false, false, true);
        std::shared_ptr<event> its_event = find_event(its_service, its_instance, its_method);
        if (its_event) {
            its_event->prepare_update_payload(_message->get_payload(), true);
            its_event->update_payload();
        }
    }
}

void routing_manager_client::on_stop_offer_service(service_t _service,
                                                  instance_t _instance,
                                                  major_version_t _major,
                                                  minor_version_t _minor) {
    (void) _major;
    (void) _minor;
    std::map<event_t, std::shared_ptr<event> > events;
    {
        std::lock_guard<std::mutex> its_lock(events_mutex_);
        auto its_events_service = events_.find(_service);
        if (its_events_service != events_.end()) {
            auto its_events_instance = its_events_service->second.find(_instance);
            if (its_events_instance != its_events_service->second.end()) {
                for (auto &e : its_events_instance->second)
                    events[e.first] = e.second;
            }
        }
    }
    for (auto &e : events) {
        e.second->unset_payload();
    }
}

void routing_manager_client::send_pending_commands() {
    for (auto &po : pending_offers_)
        send_offer_service(get_client(),
                po.service_, po.instance_,
                po.major_, po.minor_);

    send_pending_event_registrations(get_client());

    send_request_services(requests_);
}

void routing_manager_client::init_receiver() {
#ifdef __linux__
    auto its_policy_manager = configuration_->get_policy_manager();
    if (!its_policy_manager)
        return;

    its_policy_manager->store_client_to_sec_client_mapping(get_client(), get_sec_client());
    its_policy_manager->store_sec_client_to_client_mapping(get_sec_client(), get_client());
#endif
    if (!receiver_) {
        receiver_ = ep_mgr_->create_local_server(shared_from_this());
    } else {
        std::uint16_t its_port = receiver_->get_local_port();
        if (its_port != ILLEGAL_PORT)
            VSOMEIP_INFO << "Reusing local server endpoint@" << its_port << " endpoint: " << receiver_;
    }
}

void routing_manager_client::notify_remote_initially(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, const std::set<event_t> &_events_to_exclude) {
    auto its_eventgroup = find_eventgroup(_service, _instance, _eventgroup);
    if (its_eventgroup) {
        auto service_info = find_service(_service, _instance);
        for (const auto &e : its_eventgroup->get_events()) {
            if (e->is_field() && e->is_set()
                    && _events_to_exclude.find(e->get_event())
                            == _events_to_exclude.end()) {
                std::shared_ptr<message> its_notification
                    = runtime::get()->create_notification();
                its_notification->set_service(_service);
                its_notification->set_instance(_instance);
                its_notification->set_method(e->get_event());
                its_notification->set_payload(e->get_payload());
                if (service_info) {
                    its_notification->set_interface_version(service_info->get_major());
                }

                std::shared_ptr<serializer> its_serializer(get_serializer());
                if (its_serializer->serialize(its_notification.get())) {
                    {
                        std::lock_guard<std::mutex> its_lock(sender_mutex_);
                        if (sender_) {
                            send_local(sender_, VSOMEIP_ROUTING_CLIENT,
                                    its_serializer->get_data(), its_serializer->get_size(),
                                    _instance, false, protocol::id_e::NOTIFY_ID, 0);
                        }
                    }
                    its_serializer->reset();
                    put_serializer(its_serializer);
                } else {
                    VSOMEIP_ERROR << "Failed to serialize message. Check message size!";
                }
            }
        }
    }

}

uint32_t routing_manager_client::get_remote_subscriber_count(service_t _service,
        instance_t _instance, eventgroup_t _eventgroup, bool _increment) {
    std::lock_guard<std::mutex> its_lock(remote_subscriber_count_mutex_);
    uint32_t count (0);
    bool found(false);
    auto found_service = remote_subscriber_count_.find(_service);
    if (found_service != remote_subscriber_count_.end()) {
        auto found_instance = found_service->second.find(_instance);
        if (found_instance != found_service->second.end()) {
            auto found_group = found_instance->second.find(_eventgroup);
            if (found_group != found_instance->second.end()) {
                found = true;
                if (_increment) {
                    found_group->second = found_group->second + 1;
                } else {
                    if (found_group->second > 0) {
                        found_group->second = found_group->second - 1;
                    }
                }
                count = found_group->second;
            }
        }
    }
    if (!found) {
        if (_increment) {
            remote_subscriber_count_[_service][_instance][_eventgroup] = 1;
            count = 1;
        }
    }
    return count;
}

void routing_manager_client::clear_remote_subscriber_count(
        service_t _service, instance_t _instance) {
    std::lock_guard<std::mutex> its_lock(remote_subscriber_count_mutex_);
    auto found_service = remote_subscriber_count_.find(_service);
    if (found_service != remote_subscriber_count_.end()) {
        if (found_service->second.erase(_instance)) {
            if (!found_service->second.size()) {
                remote_subscriber_count_.erase(found_service);
            }
        }
    }
}

void
routing_manager_client::assign_client_timeout_cbk(
        boost::system::error_code const &_error) {

    if (!_error) {
        bool register_again(false);
        {
            std::lock_guard<std::mutex> its_lock(state_mutex_);
            if (state_ != inner_state_type_e::ST_REGISTERED) {
                state_ = inner_state_type_e::ST_DEREGISTERED;
                register_again = true;
            } else {
                VSOMEIP_INFO << __func__ << ": Will not retry registry for Client [0x"
                             << std::hex << std::setw(4) << std::setfill('0') << get_client()
                             << "] : already registered ";
            }
        }
        if (register_again) {
            std::lock_guard<std::mutex> its_lock(sender_mutex_);
            VSOMEIP_WARNING << "Client 0x" << std::hex << std::setw(4) << std::setfill('0')
                            << get_client() << " request client timeout! Trying again...";

            if (sender_) {
                sender_->restart();
            }
        }
    } else if (_error != boost::asio::error::operation_aborted) { //ignore error when timer is deliberately cancelled
        VSOMEIP_WARNING << __func__ << ": Ignoring Client 0x"
                        << std::hex << std::setw(4) << std::setfill('0') << get_client()
                        << " due to error_code: " << _error.value() ;
    }
}

void routing_manager_client::register_application_timeout_cbk(
        boost::system::error_code const &_error) {

    bool register_again(false);
    {
        std::lock_guard<std::mutex> its_lock(state_mutex_);
        if (!_error && state_ != inner_state_type_e::ST_REGISTERED) {
            state_ = inner_state_type_e::ST_DEREGISTERED;
            register_again = true;
        }
    }
    if (register_again) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        VSOMEIP_WARNING << std::hex << "Client 0x"
                        << std::hex << std::setw(4) << std::setfill('0') << get_client()
                        << " register timeout! Trying again...";

        if (sender_)
            sender_->restart();
    }
}

void routing_manager_client::send_registered_ack() {

    protocol::registered_ack_command its_command;
    its_command.set_client(get_client());

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {

        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": registered ack command serialization failed ("
            << std::dec << int(its_error) << ")";
}

bool routing_manager_client::is_client_known(client_t _client) {

    std::lock_guard<std::mutex> its_lock(known_clients_mutex_);
    return (known_clients_.find(_client) != known_clients_.end());
}

bool routing_manager_client::create_placeholder_event_and_subscribe(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        event_t _notifier, const std::shared_ptr<debounce_filter_impl_t> &_filter,
        client_t _client) {

    std::lock_guard<std::mutex> its_lock(stop_mutex_);

    bool is_inserted(false);

    if (find_service(_service, _instance)) {
        // We received an event for an existing service which was not yet
        // requested/offered. Create a placeholder field until someone
        // requests/offers this event with full information like eventgroup,
        // field/event, etc.
        std::set<eventgroup_t> its_eventgroups({ _eventgroup });
        // routing_manager_client: Always register with own client id and shadow = false
        routing_manager_base::register_event(host_->get_client(),
                _service, _instance, _notifier,
                its_eventgroups, event_type_e::ET_UNKNOWN, reliability_type_e::RT_UNKNOWN,
                std::chrono::milliseconds::zero(), false, true, nullptr, false, false,
                true);

        std::shared_ptr<event> its_event = find_event(_service, _instance, _notifier);
        if (its_event) {
            is_inserted = its_event->add_subscriber(_eventgroup, _filter, _client, false);
        }
    }

    return is_inserted;
}

void routing_manager_client::request_debounce_timeout_cbk(
        boost::system::error_code const &_error) {

    std::lock_guard<std::mutex> its_lock(state_mutex_);
    if (!_error) {
        if (requests_to_debounce_.size()) {
            if (state_ == inner_state_type_e::ST_REGISTERED) {
                send_request_services(requests_to_debounce_);
                requests_.insert(requests_to_debounce_.begin(),
                        requests_to_debounce_.end());
                requests_to_debounce_.clear();
            } else {
                {
                    std::lock_guard<std::mutex> its_lock(request_timer_mutex_);
                    request_debounce_timer_running_ = true;
                    request_debounce_timer_.expires_from_now(std::chrono::milliseconds(
                            configuration_->get_request_debouncing(host_->get_name())));
                    request_debounce_timer_.async_wait(
                            std::bind(
                                    &routing_manager_client::request_debounce_timeout_cbk,
                                    std::dynamic_pointer_cast<routing_manager_client>(shared_from_this()),
                                    std::placeholders::_1));
                    return;
                }
            }
        }
    }
    {
        std::lock_guard<std::mutex> its_lock(request_timer_mutex_);
        request_debounce_timer_running_ = false;
    }
}

void routing_manager_client::register_client_error_handler(client_t _client,
        const std::shared_ptr<endpoint> &_endpoint) {

    _endpoint->register_error_handler(
            std::bind(&routing_manager_client::handle_client_error, this, _client));
}

void routing_manager_client::handle_client_error(client_t _client) {

    if (_client != VSOMEIP_ROUTING_CLIENT) {
        VSOMEIP_INFO << "rmc::handle_client_error" << "Client 0x" << std::hex << std::setw(4)
                     << std::setfill('0') << get_client() << " handles a client error(" << std::hex
                     << std::setw(4) << std::setfill('0') << _client << ") not reconnecting";
        remove_local(_client, true);
    } else {
        bool should_reconnect(true);
        {
            std::unique_lock<std::mutex> its_lock(state_mutex_);
            should_reconnect = is_started_;
        }
        if (should_reconnect) {
            std::map<client_t, std::string> its_known_clients;
            {
                std::lock_guard<std::mutex> its_lock(known_clients_mutex_);
                its_known_clients = known_clients_;
            }
           reconnect(its_known_clients);
        }
    }
}

void routing_manager_client::send_get_offered_services_info(client_t _client, offer_type_e _offer_type) {

    protocol::offered_services_request_command its_command;
    its_command.set_client(_client);
    its_command.set_offer_type(_offer_type);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": offered service request command serialization failed ("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::send_unsubscribe_ack(
        service_t _service, instance_t _instance, eventgroup_t _eventgroup,
        remote_subscription_id_t _id) {

    protocol::unsubscribe_ack_command its_command;
    its_command.set_client(get_client());
    its_command.set_service(_service);
    its_command.set_instance(_instance);
    its_command.set_eventgroup(_eventgroup);
    its_command.set_pending_id(_id);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": unsubscribe ack command serialization failed ("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::resend_provided_event_registrations() {
    std::lock_guard<std::mutex> its_lock(state_mutex_);
    for (const event_data_t& ed : pending_event_registrations_) {
        if (ed.is_provided_) {
            send_register_event(get_client(), ed.service_, ed.instance_,
                    ed.notifier_, ed.eventgroups_, ed.type_, ed.reliability_,
                    ed.is_provided_, ed.is_cyclic_);
        }
    }
}

void routing_manager_client::send_resend_provided_event_response(pending_remote_offer_id_t _id) {

    protocol::resend_provided_events_command its_command;
    its_command.set_client(get_client());
    its_command.set_remote_offer_id(_id);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": resend provided event command serialization failed ("
            << std::dec << int(its_error) << ")";
}

#ifndef VSOMEIP_DISABLE_SECURITY
void routing_manager_client::send_update_security_policy_response(
        pending_security_update_id_t _update_id) {

    protocol::update_security_policy_response_command its_command;
    its_command.set_client(get_client());
    its_command.set_update_id(_update_id);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": update security policy response command serialization failed ("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::send_remove_security_policy_response(
        pending_security_update_id_t _update_id) {

    protocol::remove_security_policy_response_command its_command;
    its_command.set_client(get_client());
    its_command.set_update_id(_update_id);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::lock_guard<std::mutex> its_lock(sender_mutex_);
        if (sender_) {
            sender_->send(&its_buffer[0], uint32_t(its_buffer.size()));
        }
    } else
        VSOMEIP_ERROR << __func__
            << ": update security policy response command serialization failed ("
            << std::dec << int(its_error) << ")";
}

void routing_manager_client::on_update_security_credentials(
        const protocol::update_security_credentials_command &_command) {

    auto its_policy_manager = configuration_->get_policy_manager();
    if (!its_policy_manager)
        return;

    for (const auto &c : _command.get_credentials()) {
        std::shared_ptr<policy> its_policy(std::make_shared<policy>());
        boost::icl::interval_set<gid_t> its_gid_set;
        uid_t its_uid(c.first);
        gid_t its_gid(c.second);

        its_gid_set.insert(its_gid);

        its_policy->credentials_ += std::make_pair(
                boost::icl::interval<uid_t>::closed(its_uid, its_uid), its_gid_set);
        its_policy->allow_who_ = true;
        its_policy->allow_what_ = true;

        its_policy_manager->add_security_credentials(its_uid, its_gid, its_policy, get_client());
    }
}
#endif

void routing_manager_client::on_client_assign_ack(const client_t &_client) {

    std::lock_guard<std::mutex> its_lock(state_mutex_);
    if (state_ == inner_state_type_e::ST_ASSIGNING) {
        if (_client != VSOMEIP_CLIENT_UNSET) {
            state_ = inner_state_type_e::ST_ASSIGNED;

            boost::system::error_code ec;
            register_application_timer_.cancel(ec);
            host_->set_client(_client);

            if (is_started_) {
                init_receiver();
                if (receiver_) {
                    receiver_->start();

                    VSOMEIP_INFO << "Client "
                                 << std::hex << std::setw(4) << std::setfill('0') << get_client()
                                 << " (" << host_->get_name() << ") successfully connected to routing  ~> registering..";
                    register_application();
                } else {
                    VSOMEIP_WARNING << __func__ << ": (" << host_->get_name() << ":"
                                    << std::hex << std::setw(4) << std::setfill('0')
                                    << _client << ") Receiver not started. Restarting";
                    state_ = inner_state_type_e::ST_DEREGISTERED;

                    host_->set_client(VSOMEIP_CLIENT_UNSET);

                    sender_->restart();
                }
            } else {
                VSOMEIP_WARNING << __func__ << ": (" << host_->get_name() << ":"
                                << std::hex << std::setw(4) << std::setfill('0')
                                << _client << ") Not started. Discarding";
            }
        } else {
            VSOMEIP_ERROR << __func__ << ": (" << host_->get_name() << ":"
                          << std::hex << std::setw(4) << std::setfill('0')
                          << _client << ") Invalid clientID";
        }
    } else {
        VSOMEIP_WARNING << "Client " << std::hex << std::setw(4) << std::setfill('0')
                        << get_client() << " received another client identifier (" << _client
                        << "). Ignoring it. (" << static_cast<int>(state_.load()) << ")";
    }
}

void routing_manager_client::on_suspend() {

    VSOMEIP_INFO << __func__ << ": Application "
            << std::hex << std::setw(4) << std::setfill('0')
            << host_->get_client();

    std::lock_guard<std::mutex> its_lock(remote_subscriber_count_mutex_);

    // Unsubscribe everything that is left over.
    for (const auto &s : remote_subscriber_count_) {
        for (const auto &i : s.second) {
            for (const auto &e : i.second)
                routing_manager_base::unsubscribe(
                    VSOMEIP_ROUTING_CLIENT, nullptr,
                    s.first, i.first, e.first, ANY_EVENT);
        }
    }

    // Remove all entries.
    remote_subscriber_count_.clear();
}

}  // namespace vsomeip_v3
