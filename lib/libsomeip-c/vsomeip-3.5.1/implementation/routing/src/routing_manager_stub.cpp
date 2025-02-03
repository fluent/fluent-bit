// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <functional>
#include <iomanip>
#include <forward_list>

#include <boost/system/error_code.hpp>

#include <vsomeip/constants.hpp>
#include <vsomeip/error.hpp>
#include <vsomeip/payload.hpp>
#include <vsomeip/primitive_types.hpp>
#include <vsomeip/runtime.hpp>
#include <vsomeip/structured_types.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../include/routing_manager_stub.hpp"
#include "../include/routing_manager_stub_host.hpp"
#include "../include/remote_subscription.hpp"
#include "../../configuration/include/configuration.hpp"
#include "../../endpoints/include/endpoint_manager_impl.hpp"
#include "../../endpoints/include/netlink_connector.hpp"
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
#include "../../protocol/include/suspend_command.hpp"
#include "../../protocol/include/unregister_event_command.hpp"
#include "../../protocol/include/unsubscribe_ack_command.hpp"
#include "../../protocol/include/unsubscribe_command.hpp"
#include "../../protocol/include/update_security_credentials_command.hpp"
#include "../../protocol/include/update_security_policy_command.hpp"
#include "../../protocol/include/update_security_policy_response_command.hpp"
#include "../../protocol/include/config_command.hpp"
#include "../../security/include/policy_manager_impl.hpp"
#include "../../security/include/security.hpp"
#include "../../utility/include/bithelper.hpp"
#include "../../utility/include/utility.hpp"

namespace vsomeip_v3 {

routing_manager_stub::routing_manager_stub(
        routing_manager_stub_host *_host,
        const std::shared_ptr<configuration>& _configuration) :
        host_(_host),
        io_(_host->get_io()),
        watchdog_timer_(_host->get_io()),
        client_id_timer_(_host->get_io()),
        root_(nullptr),
        local_receiver_(nullptr),
        configuration_(_configuration),
        is_socket_activated_(false),
        client_registration_running_(false),
        max_local_message_size_(configuration_->get_max_message_size_local()),
        configured_watchdog_timeout_(configuration_->get_watchdog_timeout()),
        pinged_clients_timer_(io_),
        pending_security_update_id_(0)
#if defined(__linux__) || defined(ANDROID)
        , is_local_link_available_(false)
#endif
{
}

routing_manager_stub::~routing_manager_stub() {
}

void routing_manager_stub::init() {

    init_routing_endpoint();

    std::string its_env;
    char its_hostname[1024];
    if (gethostname(its_hostname, sizeof(its_hostname)) == 0)
        its_env = its_hostname;
    host_->set_client_host(its_env);
}

void routing_manager_stub::start() {
    {
        std::lock_guard<std::mutex> its_lock(used_client_ids_mutex_);
        used_client_ids_ = utility::get_used_client_ids(configuration_->get_network());
        // Wait VSOMEIP_MAX_CONNECT_TIMEOUT * 2 and expect after that time
        // that all client_ids are used have to be connected to the routing.
        // Otherwise they can be marked as "erroneous client".
        client_id_timer_.expires_from_now(std::chrono::milliseconds(VSOMEIP_MAX_CONNECT_TIMEOUT * 2));
        client_id_timer_.async_wait(
            std::bind(
                    &routing_manager_stub::on_client_id_timer_expired,
                    std::dynamic_pointer_cast<routing_manager_stub>(shared_from_this()),
                    std::placeholders::_1));
    }

#if defined(__linux__) || defined(ANDROID)
    if (configuration_->is_local_routing()) {
#else
    {
#endif // __linux__ || ANDROID
        if (!root_) {
            // application has been stopped and started again
            init_routing_endpoint();
        }
        if (root_) {
            root_->start();
        }
#if defined(__linux__) || defined(ANDROID)
    } else {
        if (local_link_connector_)
            local_link_connector_->start();
#endif
    }

    client_registration_running_ = true;
    client_registration_thread_ = std::make_shared<std::thread>(
            std::bind(&routing_manager_stub::client_registration_func, this));

    if (configuration_->is_watchdog_enabled()) {
        VSOMEIP_INFO << "Watchdog is enabled : Timeout in ms = "
                     << configuration_->get_watchdog_timeout()
                     << " : Allowed missing pongs = "
                     << configuration_->get_allowed_missing_pongs()
                     << ".";
        start_watchdog();
    } else {
        VSOMEIP_INFO << "Watchdog is disabled!";
    }

    {
        std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
        routing_info_[host_->get_client()].first = 0;
    }
}

void routing_manager_stub::stop() {
    {
        std::lock_guard<std::mutex> its_lock(client_registration_mutex_);
        client_registration_running_ = false;
        client_registration_condition_.notify_one();
    }
    if (client_registration_thread_->joinable()) {
        client_registration_thread_->join();
    }

    {
        std::lock_guard<std::mutex> its_lock(watchdog_timer_mutex_);
        watchdog_timer_.cancel();
    }

    {
        std::lock_guard<std::mutex> its_lock(used_client_ids_mutex_);
        client_id_timer_.cancel();
    }

    bool is_local_routing(configuration_->is_local_routing());

#if defined(__linux__) || defined(ANDROID)
    if (local_link_connector_)
        local_link_connector_->stop();
#endif // __linux__ || ANDROID

    if (!is_socket_activated_) {
        root_->stop();
        root_ = nullptr;

        if (is_local_routing) {
            std::stringstream its_endpoint_path;
            its_endpoint_path << utility::get_base_path(configuration_->get_network())
                    << std::hex << VSOMEIP_ROUTING_CLIENT;
    #ifdef _WIN32
            ::_unlink(its_endpoint_path.str().c_str());
    #else
            if (-1 == ::unlink(its_endpoint_path.str().c_str())) {
                VSOMEIP_ERROR << "routing_manager_stub::stop() unlink failed ("
                        << its_endpoint_path.str() << "): "<< std::strerror(errno);
            }
    #endif
        }
    }

    if (local_receiver_) {
        local_receiver_->stop();
        local_receiver_ = nullptr;

        if (is_local_routing) {
            std::stringstream its_local_receiver_path;
            its_local_receiver_path << utility::get_base_path(configuration_->get_network())
                    << std::hex << host_->get_client();
#ifdef _WIN32
            ::_unlink(its_local_receiver_path.str().c_str());
#else
            if (-1 == ::unlink(its_local_receiver_path.str().c_str())) {
                VSOMEIP_ERROR << "routing_manager_stub::stop() unlink (local receiver) failed ("
                        << its_local_receiver_path.str() << "): "<< std::strerror(errno);
            }
#endif
        }
    }
}

void routing_manager_stub::on_message(const byte_t *_data, length_t _size,
        endpoint *_receiver, bool _is_multicast,
        client_t _bound_client, const vsomeip_sec_client_t *_sec_client,
        const boost::asio::ip::address &_remote_address,
        std::uint16_t _remote_port) {

    (void)_receiver;
    (void)_is_multicast;
    (void)_remote_address;
    (void) _remote_port;
#if 0
    std::stringstream msg;
    msg << "rms::on_message: ";
    for (length_t i = 0; i < _size; ++i)
        msg << std::hex << std::setw(2) << std::setfill('0') << (int)_data[i] << " ";
    VSOMEIP_INFO << msg.str();
#endif

    client_t its_client;
    protocol::id_e its_id;
    std::string its_client_endpoint;
    service_t its_service;
    instance_t its_instance;
    method_t its_method;
    eventgroup_t its_eventgroup;
    event_t its_notifier;
    major_version_t its_major;
    minor_version_t its_minor;
    std::shared_ptr<payload> its_payload;
    bool is_reliable(false);
    client_t its_subscriber;
    uint8_t its_check_status(0);
    std::uint16_t its_subscription_id(PENDING_SUBSCRIPTION_ID);
    port_t its_port(ILLEGAL_PORT);

    std::vector<byte_t> its_buffer(_data, _data + _size);
    protocol::error_e its_error;

    // Use dummy command to deserialize id and client.
    protocol::dummy_command its_base_command;
    its_base_command.deserialize(its_buffer, its_error);
    if (its_error != protocol::error_e::ERROR_OK) {

        VSOMEIP_ERROR << __func__
                << ": deserialization of command and client identifier failed ("
                << std::dec << static_cast<int>(its_error)
                << ")";
        return;
    }

    its_client = its_base_command.get_client();
    its_id = its_base_command.get_id();

    if (configuration_->is_security_enabled()
            && configuration_->is_local_routing()
            && _bound_client != its_client) {
        VSOMEIP_WARNING << "vSomeIP Security: routing_manager_stub::on_message: "
                << "Routing Manager received a message from client "
                << std::hex << std::setw(4) << std::setfill('0')
                << its_client << " with command " << (uint32_t)its_id
                << " which doesn't match the bound client "
                << std::setw(4) << std::setfill('0') << _bound_client
                << " ~> skip message!";
        return;
    }

    switch (its_id) {

        case protocol::id_e::REGISTER_APPLICATION_ID:
        {
            protocol::register_application_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK)
                update_registration(its_command.get_client(),
                        registration_type_e::REGISTER,
                        _remote_address, its_command.get_port());
            else
                VSOMEIP_ERROR << __func__
                    << ": deserializing register application failed ("
                    << std::dec << static_cast<int>(its_error) << ")";

            break;
        }

        case protocol::id_e::DEREGISTER_APPLICATION_ID:
        {
            protocol::deregister_application_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK)
                update_registration(its_command.get_client(),
                        registration_type_e::DEREGISTER,
                        _remote_address, its_port);
            else
                VSOMEIP_ERROR << __func__
                    << ": deserializing register application failed ("
                    << std::dec << static_cast<int>(its_error) << ")";

            break;
        }

        case protocol::id_e::PONG_ID:
        {
            protocol::pong_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                on_pong(its_client);
                VSOMEIP_TRACE << "PONG("
                        << std::hex << std::setw(4) << std::setfill('0')
                        << its_client << ")";
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing pong failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::OFFER_SERVICE_ID:
        {
            protocol::offer_service_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_major = its_command.get_major();
                its_minor = its_command.get_minor();

                if (VSOMEIP_SEC_OK == configuration_->get_security()->is_client_allowed_to_offer(
                        _sec_client, its_service, its_instance)) {
                    host_->offer_service(its_client, its_service, its_instance,
                            its_major, its_minor);
                } else {
                    VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                            << " : routing_manager_stub::on_message: isn't allowed to offer "
                            << "the following service/instance " << its_service << "/" << its_instance
                            << " ~> Skip offer!";
                }
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing offer service failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::STOP_OFFER_SERVICE_ID:
        {
            protocol::stop_offer_service_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_major = its_command.get_major();
                its_minor = its_command.get_minor();

                host_->stop_offer_service(its_client,
                        its_service, its_instance,
                        its_major, its_minor);
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing stop offer service failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::SUBSCRIBE_ID:
        {
            protocol::subscribe_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_eventgroup = its_command.get_eventgroup();
                its_major = its_command.get_major();
                its_notifier = its_command.get_event();
                auto its_filter = its_command.get_filter();

                if (its_notifier == ANY_EVENT) {
                    if (host_->is_subscribe_to_any_event_allowed(_sec_client, its_client, its_service,
                            its_instance, its_eventgroup)) {
                        host_->subscribe(its_client, _sec_client, its_service, its_instance,
                                its_eventgroup, its_major, its_notifier, its_filter);
                    } else {
                        VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                                << " :  routing_manager_stub::on_message: "
                                << " subscribes to service/instance/event "
                                << its_service << "/" << its_instance << "/ANY_EVENT"
                                << " which violates the security policy ~> Skip subscribe!";
                    }
                } else {
                    if (VSOMEIP_SEC_OK == configuration_->get_security()->is_client_allowed_to_access_member(
                            _sec_client, its_service, its_instance, its_notifier)) {
                        host_->subscribe(its_client, _sec_client, its_service, its_instance,
                                its_eventgroup, its_major, its_notifier, its_filter);
                    } else {
                        VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                                << " :  routing_manager_stub::on_message: "
                                << " subscribes to service/instance/event "
                                << its_service << "/" << its_instance << "/" << its_notifier
                                << " which violates the security policy ~> Skip subscribe!";
                    }
                }
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing subscribe failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::UNSUBSCRIBE_ID:
        {
            protocol::unsubscribe_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_eventgroup = its_command.get_eventgroup();
                its_notifier = its_command.get_event();

                host_->unsubscribe(its_client, _sec_client,
                        its_service, its_instance, its_eventgroup, its_notifier);
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing unsubscribe failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::SUBSCRIBE_ACK_ID:
        {
            protocol::subscribe_ack_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_eventgroup = its_command.get_eventgroup();
                its_subscriber = its_command.get_subscriber();
                its_notifier = its_command.get_event();
                its_subscription_id = its_command.get_pending_id();

                host_->on_subscribe_ack(its_subscriber, its_service,
                        its_instance, its_eventgroup, its_notifier, its_subscription_id);

                VSOMEIP_INFO << "SUBSCRIBE ACK("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "."
                    << std::setw(4) << its_notifier << "]";
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing subscribe ack failed ("
                    << std::dec << static_cast<int>(its_error) << ")";

            break;
        }

        case protocol::id_e::SUBSCRIBE_NACK_ID:
        {
            protocol::subscribe_nack_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_eventgroup = its_command.get_eventgroup();
                its_subscriber = its_command.get_subscriber();
                its_notifier = its_command.get_event();
                its_subscription_id = its_command.get_pending_id();

                host_->on_subscribe_nack(its_subscriber, its_service,
                        its_instance, its_eventgroup, false, its_subscription_id);

                VSOMEIP_INFO << "SUBSCRIBE NACK("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "."
                    << std::setw(4) << its_notifier << "]";
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing subscribe nack failed ("
                    << std::dec << static_cast<int>(its_error) << ")";

            break;
        }

        case protocol::id_e::UNSUBSCRIBE_ACK_ID:
        {
            protocol::unsubscribe_ack_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                its_service = its_command.get_service();
                its_instance = its_command.get_instance();
                its_eventgroup = its_command.get_eventgroup();
                its_subscription_id = its_command.get_pending_id();

                host_->on_unsubscribe_ack(its_client, its_service,
                        its_instance, its_eventgroup, its_subscription_id);

                VSOMEIP_INFO << "UNSUBSCRIBE ACK("
                    << std::hex << std::setfill('0')
                    << std::setw(4) << its_client << "): ["
                    << std::setw(4) << its_service << "."
                    << std::setw(4) << its_instance << "."
                    << std::setw(4) << its_eventgroup << "]";
            } else
                VSOMEIP_ERROR << __func__
                    << ": deserializing unsubscribe ack failed ("
                    << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::SEND_ID:
        {
            protocol::send_command its_command(its_id);
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                auto its_message_data(its_command.get_message());
                if (its_message_data.size() > VSOMEIP_MESSAGE_TYPE_POS) {

                    its_service = bithelper::read_uint16_be(&its_message_data[VSOMEIP_SERVICE_POS_MIN]);
                    its_method  = bithelper::read_uint16_be(&its_message_data[VSOMEIP_METHOD_POS_MIN]);
                    its_client  = bithelper::read_uint16_be(&its_message_data[VSOMEIP_CLIENT_POS_MIN]);

                    its_instance = its_command.get_instance();
                    is_reliable = its_command.is_reliable();
                    its_check_status = its_command.get_status();

                    // Allow response messages from local proxies as answer to remote requests
                    // but check requests sent by local proxies to remote against policy.
                    if (utility::is_request(its_message_data[VSOMEIP_MESSAGE_TYPE_POS])) {
                        if (VSOMEIP_SEC_OK != configuration_->get_security()->is_client_allowed_to_access_member(
                                _sec_client, its_service, its_instance, its_method)) {
                            VSOMEIP_WARNING << "vSomeIP Security: Client 0x" << std::hex << its_client
                                    << " : routing_manager_stub::on_message: "
                                    << " isn't allowed to send a request to service/instance/method "
                                    << its_service << "/" << its_instance << "/" << its_method
                                    << " ~> Skip message!";
                            return;
                        }
                    }
                    // reduce by size of instance, flush, reliable, client and is_valid_crc flag
                    uint32_t its_contained_size = bithelper::read_uint32_be(&its_message_data[VSOMEIP_LENGTH_POS_MIN]);
                    if (its_message_data.size() != its_contained_size + VSOMEIP_SOMEIP_HEADER_SIZE) {
                        VSOMEIP_WARNING << "Received a SEND command containing message with invalid size -> skip!";
                        break;
                    }
                    host_->on_message(its_service, its_instance,
                            &its_message_data[0], length_t(its_message_data.size()),
                            is_reliable, _bound_client, _sec_client, its_check_status, false);
                }
            }
            break;
        }

        case protocol::id_e::NOTIFY_ID:
        case protocol::id_e::NOTIFY_ONE_ID:
        {
            protocol::send_command its_command(its_id);
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                auto its_message_data(its_command.get_message());
                if (its_message_data.size() > VSOMEIP_MESSAGE_TYPE_POS) {

                    its_client = its_command.get_target();
                    its_service = bithelper::read_uint16_be(&its_message_data[VSOMEIP_SERVICE_POS_MIN]);
                    its_instance = its_command.get_instance();

                    uint32_t its_contained_size = bithelper::read_uint32_be(&its_message_data[VSOMEIP_LENGTH_POS_MIN]);

                    if (its_message_data.size() != its_contained_size + VSOMEIP_SOMEIP_HEADER_SIZE) {
                        VSOMEIP_WARNING << "Received a NOTIFY command containing message with invalid size -> skip!";
                        break;
                    }

                    host_->on_notification(its_client, its_service, its_instance,
                            &its_message_data[0], length_t(its_message_data.size()),
                            its_id == protocol::id_e::NOTIFY_ONE_ID);
                    break;
                }
            }
            break;
        }

        case protocol::id_e::REQUEST_SERVICE_ID:
        {
            protocol::request_service_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                its_client = its_command.get_client();
                auto its_requests = its_command.get_services();

                std::set<protocol::service> its_allowed_requests;
                for (const auto &r : its_requests) {
                    if (VSOMEIP_SEC_OK == configuration_->get_security()->is_client_allowed_to_request(
                            _sec_client, r.service_, r.instance_)) {
                        host_->request_service(its_client,
                            r.service_, r.instance_, r.major_, r.minor_);
                        its_allowed_requests.insert(r);
                    }
                }
                if (configuration_->is_security_enabled()) {
                    handle_credentials(its_client, its_allowed_requests);
                }
                handle_requests(its_client, its_allowed_requests);
            } else
                VSOMEIP_ERROR << __func__ << ": request service deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";

            break;
        }

        case protocol::id_e::RELEASE_SERVICE_ID:
        {
            protocol::release_service_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                host_->release_service(its_command.get_client(),
                        its_command.get_service(), its_command.get_instance());
            } else
                VSOMEIP_ERROR << __func__ << ": release service deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::REGISTER_EVENT_ID:
        {
            protocol::register_events_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                its_client = its_command.get_client();
                for(std::size_t i = 0; i < its_command.get_num_registrations(); i++) {
                    protocol::register_event register_event;
                    if (!its_command.get_registration_at(i, register_event)) {
                        continue;
                    }

                    its_service = register_event.get_service();
                    its_instance = register_event.get_instance();

                    if (register_event.is_provided()
                            && !configuration_->is_offered_remote(its_service, its_instance)) {
                        continue;
                    }

                    host_->register_shadow_event(its_client,
                            its_service, its_instance,
                            register_event.get_event(), register_event.get_eventgroups(),
                            register_event.get_event_type(), register_event.get_reliability(),
                            register_event.is_provided(), register_event.is_cyclic());

                    VSOMEIP_INFO << "REGISTER EVENT("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << its_client << "): ["
                        << std::setw(4) << its_service << "."
                        << std::setw(4) << its_instance << "."
                        << std::setw(4) << register_event.get_event()
                        << ":eventtype=" << std::dec << (int)register_event.get_event_type()
                        << ":is_provided=" << std::boolalpha << register_event.is_provided()
                        << ":reliable=" << (int)register_event.get_reliability() << "]";
                }


            } else
                VSOMEIP_ERROR << __func__ << ": register event deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::UNREGISTER_EVENT_ID:
        {
            protocol::unregister_event_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                host_->unregister_shadow_event(its_command.get_client(),
                        its_command.get_service(), its_command.get_instance(),
                        its_command.get_event(), its_command.is_provided());

                VSOMEIP_INFO << "UNREGISTER EVENT("
                        << std::hex << std::setfill('0')
                        << std::setw(4) << its_command.get_client() << "): ["
                        << std::setw(4) << its_command.get_service() << "."
                        << std::setw(4) << its_command.get_instance() << "."
                        << std::setw(4) << its_command.get_event()
                        << ":is_provider=" << std::boolalpha << its_command.is_provided() << "]";
            } else
                VSOMEIP_ERROR << __func__ << ": unregister event deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::REGISTERED_ACK_ID:
        {
            protocol::registered_ack_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                VSOMEIP_INFO << "REGISTERED_ACK("
                        << std::hex << std::setw(4) << std::setfill('0')
                        << its_command.get_client() << ")";
            } else
                VSOMEIP_ERROR << __func__ << ": registered ack deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::OFFERED_SERVICES_REQUEST_ID:
        {
            protocol::offered_services_request_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {

                on_offered_service_request(its_command.get_client(), its_command.get_offer_type());
            } else
                VSOMEIP_ERROR << __func__ << ": offer service request deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::RESEND_PROVIDED_EVENTS_ID:
        {
            protocol::resend_provided_events_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                host_->on_resend_provided_events_response(its_command.get_remote_offer_id());
                VSOMEIP_INFO << "RESEND_PROVIDED_EVENTS("
                    << std::hex << std::setw(4) << std::setfill('0') << its_client << ")";
            } else
                VSOMEIP_ERROR << __func__ << ": resend provided events deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }
#ifndef VSOMEIP_DISABLE_SECURITY
        case protocol::id_e::UPDATE_SECURITY_POLICY_RESPONSE_ID:
        {
            protocol::update_security_policy_response_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                on_security_update_response(its_command.get_update_id(), its_client);
            } else
                VSOMEIP_ERROR << __func__ << ": update security policy deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
            break;
        }

        case protocol::id_e::REMOVE_SECURITY_POLICY_RESPONSE_ID:
        {
            protocol::remove_security_policy_response_command its_command;
            its_command.deserialize(its_buffer, its_error);
            if (its_error == protocol::error_e::ERROR_OK) {
                on_security_update_response(its_command.get_update_id(), its_client);
            } else
                VSOMEIP_ERROR << __func__ << ": update security policy deserialization failed ("
                        << std::dec << static_cast<int>(its_error) << ")";
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
            VSOMEIP_WARNING << __func__ << ": Received an unhandled command ("
                << std::dec << static_cast<int>(its_id) << ")";
    }
}

void routing_manager_stub::add_known_client(client_t _client, const std::string &_client_host) {
    host_->add_known_client(_client, _client_host);
}

void routing_manager_stub::on_register_application(client_t _client) {

    auto endpoint = host_->find_local(_client);
    if (endpoint) {
        VSOMEIP_WARNING << "Reregistering application: " << std::hex << _client
                << ". Last registration might have been taken too long.";
        endpoint->stop();
        endpoint->start();
    } else {
        endpoint = host_->find_or_create_local(_client);
        {
            std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
            routing_info_[_client].first = 0;
        }
#ifndef VSOMEIP_DISABLE_SECURITY
        if (configuration_->is_local_routing()) {
            vsomeip_sec_client_t its_sec_client;
            std::set<std::shared_ptr<policy> > its_policies;

            bool has_mapping = configuration_->get_policy_manager()
                    ->get_client_to_sec_client_mapping(_client, its_sec_client);
            if (has_mapping) {
                if (its_sec_client.port == VSOMEIP_SEC_PORT_UNUSED) {
                    get_requester_policies(its_sec_client.user,
                            its_sec_client.group, its_policies);
                }

                if (!its_policies.empty())
                    send_requester_policies({ _client }, its_policies);
            }
        }
#endif // !VSOMEIP_DISABLE_SECURITY
    }
}

void routing_manager_stub::on_deregister_application(client_t _client) {
    std::vector<
            std::tuple<service_t, instance_t,
                       major_version_t, minor_version_t>> services_to_report;
    {
        std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
        auto its_info = routing_info_.find(_client);
        if (its_info != routing_info_.end()) {
            for (const auto &its_service : its_info->second.second) {
                for (const auto &its_instance : its_service.second) {
                    const auto its_version = its_instance.second;
                    services_to_report.push_back(
                            std::make_tuple(its_service.first,
                                    its_instance.first, its_version.first,
                                    its_version.second));
                }
            }
        }
        routing_info_.erase(_client);
    }
    for (const auto &s : services_to_report) {
        host_->on_availability(std::get<0>(s), std::get<1>(s),
                availability_state_e::AS_UNAVAILABLE,
                std::get<2>(s), std::get<3>(s));
        host_->on_stop_offer_service(_client, std::get<0>(s), std::get<1>(s),
                std::get<2>(s), std::get<3>(s));
    }
}

void
routing_manager_stub::on_offered_service_request(client_t _client,
        offer_type_e _offer_type) {

    protocol::offered_services_response_command its_command;
    its_command.set_client(_client);

    for (const auto& found_client : routing_info_) {
        // skip services which are offered on remote hosts
        if (found_client.first != VSOMEIP_ROUTING_CLIENT) {
            for (const auto &s : found_client.second.second) {
                for (const auto &i : s.second) {
                    uint16_t its_reliable_port
                        = configuration_->get_reliable_port(s.first, i.first);
                    uint16_t its_unreliable_port
                        = configuration_->get_unreliable_port(s.first, i.first);
                    bool has_port = (its_reliable_port != ILLEGAL_PORT
                            || its_unreliable_port != ILLEGAL_PORT);

                    if (_offer_type == offer_type_e::OT_ALL
                            || (_offer_type == offer_type_e::OT_LOCAL && !has_port)
                            || (_offer_type == offer_type_e::OT_REMOTE && has_port)) {

                        protocol::service its_service(s.first, i.first,
                                i.second.first, i.second.second);
                        its_command.add_service(its_service);
                    }
                }
            }
        }
    }

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::shared_ptr<endpoint> its_endpoint = host_->find_local(_client);
        if (its_endpoint)
            its_endpoint->send(&its_buffer[0], uint32_t(its_buffer.size()));
    }
}

void routing_manager_stub::client_registration_func(void) {
#if defined(__linux__) || defined(ANDROID)
    {
        std::stringstream s;
        s << std::hex << std::setw(4) << std::setfill('0')
            << host_->get_client() << "_client_reg";
        pthread_setname_np(pthread_self(),s.str().c_str());
    }
#endif
    std::unique_lock<std::mutex> its_lock(client_registration_mutex_);
    while (client_registration_running_) {
        while (!pending_client_registrations_.size() && client_registration_running_) {
            client_registration_condition_.wait(its_lock);
        }

        std::map<client_t, std::vector<registration_type_e>> its_registrations(
                pending_client_registrations_);
        pending_client_registrations_.clear();
        its_lock.unlock();

        for (const auto& r : its_registrations) {
            for (auto b : r.second) {
                if (b == registration_type_e::REGISTER) {
                    on_register_application(r.first);
                } else {
                    on_deregister_application(r.first);
                }
                // Inform (de)registered client. All others will be informed after
                // the client acknowledged its registered state!
                // Don't inform client if we deregister because of an client
                // endpoint error to avoid writing in an already closed socket
                if (b != registration_type_e::DEREGISTER_ON_ERROR) {
                    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
                    add_connection(r.first, r.first);
                    protocol::routing_info_entry its_entry;
                    its_entry.set_client(r.first);
                    if (b == registration_type_e::REGISTER) {
                        boost::asio::ip::address its_address;
                        port_t its_port;

                        its_entry.set_type(protocol::routing_info_entry_type_e::RIE_ADD_CLIENT);
                        if (host_->get_guest(r.first, its_address, its_port)) {
                            its_entry.set_address(its_address);
                            its_entry.set_port(its_port);
                        }
#ifndef VSOMEIP_DISABLE_SECURITY
                        // distribute updated security config to new clients
                        send_cached_security_policies(r.first);
#endif // !VSOMEIP_DISABLE_SECURITY
                    } else {
                        its_entry.set_type(protocol::routing_info_entry_type_e::RIE_DELETE_CLIENT);
                    }
                    send_client_routing_info(r.first, its_entry);
                }
                if (b != registration_type_e::REGISTER) {
                    {
                        std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
                        auto find_connections = connection_matrix_.find(r.first);
                        if (find_connections != connection_matrix_.end()) {
                            for (auto its_client : find_connections->second) {
                                if (its_client != r.first &&
                                        its_client != VSOMEIP_ROUTING_CLIENT &&
                                        its_client != get_client()) {
                                    protocol::routing_info_entry its_entry;
                                    its_entry.set_type(protocol::routing_info_entry_type_e::RIE_DELETE_CLIENT);
                                    its_entry.set_client(r.first);
                                    send_client_routing_info(its_client, its_entry);
                                }
                            }
                            remove_source(r.first);
                        }
                        for (const auto &its_connections : connection_matrix_) {
                            remove_connection(its_connections.first, r.first);
                        }
                        service_requests_.erase(r.first);
                    }
                    // Don't remove client ID to UID maping as same client
                    // could have passed its credentials again
                    host_->remove_local(r.first, false);
                    utility::release_client_id(configuration_->get_network(), r.first);
                }
            }
        }
        its_lock.lock();
    }
}

void routing_manager_stub::init_routing_endpoint() {

#if defined(__linux__) || defined(ANDROID)
    if (configuration_->is_local_routing()) {
#else
    {
#endif // __linux__ || ANDROID
        bool is_successful = host_->get_endpoint_manager()->create_routing_root(
                root_, is_socket_activated_, shared_from_this());

        if (!is_successful) {
            VSOMEIP_WARNING << "Routing root creating (partially) failed. Please check your configuration.";
        }
#if defined(__linux__) || defined(ANDROID)
    } else {
        auto its_host_address = configuration_->get_routing_host_address();
        local_link_connector_ = std::make_shared<netlink_connector>(
                io_, its_host_address, boost::asio::ip::address(), false); // routing host doesn't need link up
        if (local_link_connector_) {
            local_link_connector_->register_net_if_changes_handler(
                std::bind(&routing_manager_stub::on_net_state_change,
                    this, std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
        }
#endif // __linux__ || ANDROID
    }
}

#if defined(__linux__) || defined(ANDROID)
void
routing_manager_stub::on_net_state_change(
        bool _is_interface, const std::string &_name, bool _is_available) {

    VSOMEIP_INFO << __func__
        << "("<< std::hex << std::this_thread::get_id() << "): "
        << std::boolalpha << _is_interface << " "
        << _name << " "
        << std::boolalpha << _is_available;

    if (_is_interface) {
        if (_is_available) {
            if (!is_local_link_available_) {
                is_local_link_available_ = true;
                if (!root_)
                    (void)host_->get_endpoint_manager()->create_routing_root(
                        root_, is_socket_activated_, shared_from_this());
                if (root_) {
                    VSOMEIP_INFO << __func__
                            << ": Starting routing root.";
                    root_->start();
                } else
                    VSOMEIP_WARNING << "Routing root creating (partially) failed. "
                        "Please check your configuration.";
            }
        } else {
            if (is_local_link_available_) {

                VSOMEIP_INFO << __func__
                        << ": Stopping routing root.";
                root_->stop();

                routing_info_.clear();
                host_->clear_local_services();

                is_local_link_available_ = false;
            }
        }
    }
}
#endif // __linux__ || ANDROID

void routing_manager_stub::on_offer_service(client_t _client,
        service_t _service, instance_t _instance, major_version_t _major, minor_version_t _minor) {
    if (_client == host_->get_client()) {
        create_local_receiver();
    }

    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
    routing_info_[_client].second[_service][_instance] = std::make_pair(_major, _minor);
    if (configuration_->is_security_enabled()) {
        distribute_credentials(_client, _service, _instance);
    }
    inform_requesters(_client, _service, _instance, _major, _minor,
            protocol::routing_info_entry_type_e::RIE_ADD_SERVICE_INSTANCE, true);
}

void routing_manager_stub::on_stop_offer_service(client_t _client,
        service_t _service, instance_t _instance,  major_version_t _major, minor_version_t _minor) {
    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
    auto found_client = routing_info_.find(_client);
    if (found_client != routing_info_.end()) {
        auto found_service = found_client->second.second.find(_service);
        if (found_service != found_client->second.second.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                auto found_version = found_instance->second;
                if( _major == found_version.first && _minor == found_version.second) {
                    found_service->second.erase(_instance);
                    if (0 == found_service->second.size()) {
                        found_client->second.second.erase(_service);
                    }
                    inform_requesters(_client, _service, _instance, _major, _minor,
                            protocol::routing_info_entry_type_e::RIE_DELETE_SERVICE_INSTANCE, false);
                } else if( _major == DEFAULT_MAJOR && _minor == DEFAULT_MINOR) {
                    found_service->second.erase(_instance);
                    if (0 == found_service->second.size()) {
                        found_client->second.second.erase(_service);
                    }
                    inform_requesters(_client, _service, _instance, _major, _minor,
                            protocol::routing_info_entry_type_e::RIE_DELETE_SERVICE_INSTANCE, false);
                }
            }
        }
    }
}

void routing_manager_stub::send_client_credentials(const client_t _target,
        std::set<std::pair<uid_t, gid_t>> &_credentials) {

    std::shared_ptr<endpoint> its_endpoint = host_->find_local(_target);
    if (its_endpoint) {
        protocol::update_security_credentials_command its_command;
        its_command.set_client(_target);
        its_command.set_credentials(_credentials);

#if 0
        std::stringstream msg;
        msg << "rms::send_credentials_info to (" << std::hex << _target << "): ";
        for (uint32_t i = 0; i < its_size; ++i)
            msg << std::hex << std::setw(2) << std::setfill('0') << (int)its_command[i] << " ";
        VSOMEIP_INFO << msg.str();
#endif

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            if(its_buffer.size() <= max_local_message_size_
                    || VSOMEIP_MAX_LOCAL_MESSAGE_SIZE == 0) {
                its_endpoint->send(&its_buffer[0], uint32_t(its_buffer.size()));
            } else
                VSOMEIP_ERROR << __func__
                    << ": Credentials info exceeds maximum message size: Can't send!";

        } else
            VSOMEIP_ERROR << __func__
                << ": update security credentials command serialization failed ("
                << static_cast<int>(its_error)
                << ")";
    } else
        VSOMEIP_ERROR << __func__
            << ": Sending credentials to client ["
            << std::hex << std::setw(4) << std::setfill('0')
            << _target
            << "] failed";
}

void routing_manager_stub::send_client_routing_info(const client_t _target,
        protocol::routing_info_entry &_entry) {

    std::vector<protocol::routing_info_entry> its_entries;
    its_entries.emplace_back(_entry);
    send_client_routing_info(_target, std::move(its_entries));
}

void routing_manager_stub::send_client_routing_info(const client_t _target,
        std::vector<protocol::routing_info_entry> &&_entries) {

    auto its_target_endpoint = host_->find_local(_target);
    if (its_target_endpoint) {

        protocol::routing_info_command its_command;
        its_command.set_client(get_client());
        its_command.set_entries(std::move(_entries));

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            its_target_endpoint->send(&its_buffer[0], uint32_t(its_buffer.size()));
        } else
            VSOMEIP_ERROR << __func__
                << ": routing info command serialization failed ("
                << static_cast<int>(its_error)
                << ")";
    } else
        VSOMEIP_ERROR << __func__
            << ": Sending routing info to client ["
            << std::hex << std::setw(4) << std::setfill('0')
            << _target
            << "] failed";
}

void routing_manager_stub::distribute_credentials(client_t _hoster, service_t _service, instance_t _instance) {
    std::set<std::pair<uid_t, gid_t>> its_credentials;
    std::set<client_t> its_requesting_clients;
    // search for clients which shall receive the credentials
    for (auto its_requesting_client : service_requests_) {
        auto its_service = its_requesting_client.second.find(_service);
        if (its_service != its_requesting_client.second.end()) {
            if (its_service->second.find(_instance) != its_service->second.end()
                    || its_service->second.find(ANY_INSTANCE) != its_service->second.end()) {
                 its_requesting_clients.insert(its_requesting_client.first);
            }
        }
    }

    // search for UID / GID linked with the client ID that offers the requested services
    vsomeip_sec_client_t its_sec_client;
    if (configuration_->get_policy_manager()->get_client_to_sec_client_mapping(_hoster, its_sec_client)) {
        std::pair<uid_t, gid_t> its_uid_gid;
        its_uid_gid.first = its_sec_client.user;
        its_uid_gid.second = its_sec_client.group;
        its_credentials.insert(its_uid_gid);
        for (auto its_requesting_client : its_requesting_clients) {
            vsomeip_sec_client_t its_requester_sec_client;
            if (configuration_->get_policy_manager()->get_client_to_sec_client_mapping(
                    its_requesting_client, its_requester_sec_client)) {
                if (!utility::compare(its_sec_client, its_requester_sec_client))
                    send_client_credentials(its_requesting_client, its_credentials);
            }
        }
    }
}

void routing_manager_stub::inform_requesters(client_t _hoster, service_t _service,
        instance_t _instance, major_version_t _major, minor_version_t _minor,
        protocol::routing_info_entry_type_e _type, bool _inform_service) {

    boost::asio::ip::address its_address;
    port_t its_port;

    for (auto its_client : service_requests_) {
        auto its_service = its_client.second.find(_service);
        if (its_service != its_client.second.end()) {
            if (its_service->second.find(_instance) != its_service->second.end()
                    || its_service->second.find(ANY_INSTANCE) != its_service->second.end()) {
                if (_inform_service) {
                    if (_hoster != VSOMEIP_ROUTING_CLIENT &&
                            _hoster != host_->get_client()) {
                        if (!is_connected(_hoster, its_client.first)) {
                            add_connection(_hoster, its_client.first);
                            protocol::routing_info_entry its_entry;
                            its_entry.set_type(protocol::routing_info_entry_type_e::RIE_ADD_CLIENT);
                            its_entry.set_client(its_client.first);
                            if (host_->get_guest(its_client.first, its_address, its_port)) {
                                its_entry.set_address(its_address);
                                its_entry.set_port(its_port);
                            }
                            send_client_routing_info(_hoster, its_entry);
                        }
                    }
                }
                if (its_client.first != VSOMEIP_ROUTING_CLIENT &&
                        its_client.first != get_client()) {
                    add_connection(its_client.first, _hoster);
                    protocol::routing_info_entry its_entry;
                    its_entry.set_type(_type);
                    its_entry.set_client(_hoster);
                    if ((_type == protocol::routing_info_entry_type_e::RIE_ADD_CLIENT
                            || _type == protocol::routing_info_entry_type_e::RIE_ADD_SERVICE_INSTANCE)
                            && host_->get_guest(_hoster, its_address, its_port)) {
                        its_entry.set_address(its_address);
                        its_entry.set_port(its_port);
                    }
                    its_entry.add_service({ _service, _instance, _major, _minor} );
                    send_client_routing_info(its_client.first, its_entry);
                }
            }
        }
    }
}

void routing_manager_stub::broadcast(const std::vector<byte_t> &_command) const {
    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
    for (const auto& a : routing_info_) {
        if (a.first != VSOMEIP_ROUTING_CLIENT && a.first != host_->get_client()) {
            std::shared_ptr<endpoint> its_endpoint
                = host_->find_local(a.first);
            if (its_endpoint) {
                its_endpoint->send(&_command[0], uint32_t(_command.size()));
            }
        }
    }
}

bool routing_manager_stub::send_subscribe(
        const std::shared_ptr<endpoint>& _target, client_t _client,
        service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, major_version_t _major,
        event_t _event, const std::shared_ptr<debounce_filter_impl_t> &_filter,
        remote_subscription_id_t _id) {

    bool has_sent(false);

    if (_target) {

        protocol::subscribe_command its_command;
        its_command.set_client(_client);
        its_command.set_service(_service);
        its_command.set_instance(_instance);
        its_command.set_eventgroup(_eventgroup);
        its_command.set_major(_major);
        its_command.set_event(_event);
        its_command.set_filter(_filter);
        its_command.set_pending_id(_id);

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            has_sent = _target->send(&its_buffer[0], uint32_t(its_buffer.size()));
        } else
            VSOMEIP_ERROR << __func__
                << ": subscribe command serialization failed ("
                << std::dec << int(its_error) << ")";

    } else {
        VSOMEIP_WARNING << __func__
            << " Couldn't send subscription to local client ["
            << std::hex << std::setfill('0')
            << std::setw(4) << _service << "."
            << std::setw(4) << _instance << "."
            << std::setw(4) << _eventgroup << "."
            << std::setw(4) << _event << "]"
            << " subscriber: " << std::setw(4) << _client;
    }

    return has_sent;
}

bool routing_manager_stub::send_unsubscribe(
        const std::shared_ptr<endpoint>& _target,
        client_t _client, service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event,
        remote_subscription_id_t _id) {

    bool has_sent(false);

    if (_target) {

        protocol::unsubscribe_command its_command;
        its_command.set_client(_client);
        its_command.set_service(_service);
        its_command.set_instance(_instance);
        its_command.set_eventgroup(_eventgroup);
        its_command.set_event(_event);
        its_command.set_pending_id(_id);

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            has_sent = _target->send(&its_buffer[0], uint32_t(its_buffer.size()));
        } else
            VSOMEIP_ERROR << __func__
                << ": unsubscribe command serialization failed ("
                << std::dec << int(its_error) << ")";
    } else {
        VSOMEIP_WARNING << __func__
            << " Couldn't send unsubscription to local client ["
            << std::hex << std::setfill('0')
            << std::setw(4) << _service << "."
            << std::setw(4) << _instance << "."
            << std::setw(4) << _eventgroup << "."
            << std::setw(4) << _event << "]"
            << " subscriber: "<< std::setw(4) << _client;
    }

    return has_sent;
}

bool routing_manager_stub::send_expired_subscription(
        const std::shared_ptr<endpoint>& _target,
        client_t _client, service_t _service, instance_t _instance,
        eventgroup_t _eventgroup, event_t _event,
        remote_subscription_id_t _id) {

    bool has_sent(false);

    if (_target) {

        protocol::expire_command its_command;
        its_command.set_client(_client);
        its_command.set_service(_service);
        its_command.set_instance(_instance);
        its_command.set_eventgroup(_eventgroup);
        its_command.set_event(_event);
        its_command.set_pending_id(_id);

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            has_sent = _target->send(&its_buffer[0], uint32_t(its_buffer.size()));
        } else
            VSOMEIP_ERROR << __func__
                << ": unsubscribe command serialization failed ("
                << std::dec << int(its_error) << ")";
    } else {
        VSOMEIP_WARNING << __func__
            << " Couldn't send expired subscription to local client ["
            << std::hex << std::setfill('0')
            << std::setw(4) << _service << "."
            << std::setw(4) << _instance << "."
            << std::setw(4) << _eventgroup << "."
            << std::setw(4) << _event << "]"
            << " subscriber: "<< std::setw(4) << _client;
    }

    return has_sent;
}

void routing_manager_stub::send_subscribe_ack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event) {

    std::shared_ptr<endpoint> its_target = host_->find_local(_client);
    if (its_target) {

        protocol::subscribe_ack_command its_command;
        its_command.set_client(get_client());
        its_command.set_service(_service);
        its_command.set_instance(_instance);
        its_command.set_eventgroup(_eventgroup);
        its_command.set_subscriber(_client);
        its_command.set_event(_event);

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            (void)its_target->send(&its_buffer[0], uint32_t(its_buffer.size()));
        } else
            VSOMEIP_ERROR << __func__
                << ": subscribe ack command serialization failed ("
                << std::dec << int(its_error) << ")";
    }
}

void routing_manager_stub::send_subscribe_nack(client_t _client, service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event) {

    std::shared_ptr<endpoint> its_target = host_->find_local(_client);
    if (its_target) {

        protocol::subscribe_nack_command its_command;
        its_command.set_client(get_client());
        its_command.set_service(_service);
        its_command.set_instance(_instance);
        its_command.set_eventgroup(_eventgroup);
        its_command.set_subscriber(_client);
        its_command.set_event(_event);

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK) {
            (void)its_target->send(&its_buffer[0], uint32_t(its_buffer.size()));
        } else
            VSOMEIP_ERROR << __func__
                << ": subscribe ack command serialization failed ("
                << std::dec << int(its_error) << ")";
    }
}

bool routing_manager_stub::contained_in_routing_info(
        client_t _client, service_t _service, instance_t _instance,
        major_version_t _major, minor_version_t _minor) const {
    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
    auto found_client = routing_info_.find(_client);
    if (found_client != routing_info_.end()) {
        auto found_service = found_client->second.second.find(_service);
        if (found_service != found_client->second.second.end()) {
            auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                if (found_instance->second.first == _major
                        && found_instance->second.second == _minor) {
                    return true;
                }
            }
        }
    }
    return false;
}

// Watchdog
void routing_manager_stub::broadcast_ping() const {

    protocol::ping_command its_command;

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK)
        broadcast(its_buffer);
    else
        VSOMEIP_ERROR << __func__
            << ": ping command serialization failed ("
            << std::dec << int(its_error) << ")";
}

void routing_manager_stub::on_pong(client_t _client) {
    {
        std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
        auto found_info = routing_info_.find(_client);
        if (found_info != routing_info_.end()) {
            found_info->second.first = 0;
        } else {
            VSOMEIP_ERROR << "Received PONG from unregistered application: "
                    << std::hex << std::setw(4) << std::setfill('0') << _client;
        }
    }
    remove_from_pinged_clients(_client);
    host_->on_pong(_client);
}

void routing_manager_stub::start_watchdog() {

    auto its_callback =
            [this](boost::system::error_code const &_error) {
                if (!_error)
                    check_watchdog();
            };
    {
        std::lock_guard<std::mutex> its_lock(watchdog_timer_mutex_);
        // Divide / 2 as start and check sleep each
        watchdog_timer_.expires_from_now(
                std::chrono::milliseconds(
                        configuration_->get_watchdog_timeout() / 2));

        watchdog_timer_.async_wait(its_callback);
    }
}

void routing_manager_stub::check_watchdog() {
    {
        std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
        for (auto i = routing_info_.begin(); i != routing_info_.end(); ++i) {
            i->second.first++;
        }
    }
    broadcast_ping();


    auto its_callback = [this](boost::system::error_code const &_error) {
                (void)_error;
                std::list< client_t > lost;
                {
                    std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
                    for (const auto& i : routing_info_) {
                        if (i.first > 0 && i.first != host_->get_client()) {
                            if (i.second.first > configuration_->get_allowed_missing_pongs()) {
                                VSOMEIP_WARNING << "Lost contact to application " << std::hex << (int)i.first;
                                lost.push_back(i.first);
                            }
                        }
                    }
                }
                for (auto i : lost) {
                    host_->handle_client_error(i);
                }
                start_watchdog();
            };
    {
        std::lock_guard<std::mutex> its_lock(watchdog_timer_mutex_);
        watchdog_timer_.expires_from_now(
                std::chrono::milliseconds(
                        configuration_->get_watchdog_timeout() / 2));
        watchdog_timer_.async_wait(its_callback);
    }
}

void routing_manager_stub::create_local_receiver() {
    std::lock_guard<std::mutex> its_lock(local_receiver_mutex_);

    if (local_receiver_) {
        return;
    }
#ifdef __linux__
    else if (!configuration_->get_policy_manager()->check_credentials(get_client(), host_->get_sec_client())) {
        VSOMEIP_ERROR << "vSomeIP Security: Client 0x" << std::hex << get_client()
                << " : routing_manager_stub::create_local_receiver:  isn't allowed"
                << " to create a server endpoint due to credential check failed!";
        return;
    }
#endif
    local_receiver_ = std::static_pointer_cast<endpoint_manager_base>(
            host_->get_endpoint_manager())->create_local_server(shared_from_this());

    if (local_receiver_)
        local_receiver_->start();
}

bool routing_manager_stub::send_ping(client_t _client) {

    bool has_sent(false);

    std::shared_ptr<endpoint> its_endpoint = host_->find_local(_client);
    if (its_endpoint) {
        std::lock_guard<std::mutex> its_lock(pinged_clients_mutex_);

        if (pinged_clients_.find(_client) != pinged_clients_.end()) {
            // client was already pinged: don't ping again and wait for answer
            // or timeout of previous ping.
            has_sent = true;
        } else {
            boost::system::error_code ec;
            pinged_clients_timer_.cancel(ec);
            if (ec) {
                VSOMEIP_ERROR << "routing_manager_stub::send_ping cancellation of "
                        "timer failed: " << ec.message();
            }
            const std::chrono::steady_clock::time_point now(
                    std::chrono::steady_clock::now());

            std::chrono::milliseconds next_timeout(configured_watchdog_timeout_);
            for (const auto &tp : pinged_clients_) {
                const std::chrono::milliseconds its_clients_timeout =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - tp.second);
                if (next_timeout > its_clients_timeout) {
                    next_timeout = its_clients_timeout;
                }
            }

            pinged_clients_[_client] = now;

            ec.clear();
            pinged_clients_timer_.expires_from_now(next_timeout, ec);
            if (ec) {
                VSOMEIP_ERROR << "routing_manager_stub::send_ping setting "
                    "expiry time of timer failed: " << ec.message();
            }
            pinged_clients_timer_.async_wait(
                    std::bind(&routing_manager_stub::on_ping_timer_expired, this,
                            std::placeholders::_1));

            protocol::ping_command its_command;

            std::vector<byte_t> its_buffer;
            protocol::error_e its_error;
            its_command.serialize(its_buffer, its_error);

            if (its_error == protocol::error_e::ERROR_OK)
                has_sent = its_endpoint->send(&its_buffer[0], uint32_t(its_buffer.size()));
            else
                VSOMEIP_ERROR << __func__
                    << ": ping command serialization failed ("
                    << std::dec << int(its_error) << ")";
        }
    }

    return has_sent;
}

void routing_manager_stub::on_ping_timer_expired(
        boost::system::error_code const &_error) {
    if(_error) {
        return;
    }
    std::forward_list<client_t> timed_out_clients;
    std::chrono::milliseconds next_timeout(configured_watchdog_timeout_);
    bool pinged_clients_remaining(false);

    {
        // remove timed out clients
        std::lock_guard<std::mutex> its_lock(pinged_clients_mutex_);
        const std::chrono::steady_clock::time_point now(
                std::chrono::steady_clock::now());

        for (auto client_iter = pinged_clients_.begin();
                  client_iter != pinged_clients_.end(); ) {
            if ((now - client_iter->second) >= configured_watchdog_timeout_) {
                timed_out_clients.push_front(client_iter->first);
                client_iter = pinged_clients_.erase(client_iter);
            } else {
                ++client_iter;
            }
        }
        pinged_clients_remaining = (pinged_clients_.size() > 0);

        if(pinged_clients_remaining) {
            // find out next timeout
            for (const auto &tp : pinged_clients_) {
                const std::chrono::milliseconds its_clients_timeout =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - tp.second);
                if (next_timeout > its_clients_timeout) {
                    next_timeout = its_clients_timeout;
                }
            }
        }
    }

    for (const client_t client : timed_out_clients) {
        // Client did not respond to ping. Report client_error in order to
        // accept pending offers trying to replace the offers of the client
        // that seems to be gone.
        host_->handle_client_error(client);
    }
    if (pinged_clients_remaining) {
        boost::system::error_code ec;
        pinged_clients_timer_.expires_from_now(next_timeout, ec);
        if (ec) {
            VSOMEIP_ERROR<< "routing_manager_stub::on_ping_timer_expired "
            "setting expiry time of timer failed: " << ec.message();
        }
        pinged_clients_timer_.async_wait(
                std::bind(&routing_manager_stub::on_ping_timer_expired, this,
                        std::placeholders::_1));
    }
}

void routing_manager_stub::remove_from_pinged_clients(client_t _client) {
    std::lock_guard<std::mutex> its_lock(pinged_clients_mutex_);
    if (!pinged_clients_.size()) {
        return;
    }
    boost::system::error_code ec;
    pinged_clients_timer_.cancel(ec);
    if (ec) {
        VSOMEIP_ERROR << "routing_manager_stub::remove_from_pinged_clients "
                "cancellation of timer failed: " << ec.message();
    }
    pinged_clients_.erase(_client);

    if (!pinged_clients_.size()) {
            return;
    }
    const std::chrono::steady_clock::time_point now(
            std::chrono::steady_clock::now());
    std::chrono::milliseconds next_timeout(configured_watchdog_timeout_);
    // find out next timeout
    for (const auto &tp : pinged_clients_) {
        const std::chrono::milliseconds its_clients_timeout =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - tp.second);
        if (next_timeout > its_clients_timeout) {
            next_timeout = its_clients_timeout;
        }
    }
    ec.clear();
    pinged_clients_timer_.expires_from_now(next_timeout, ec);
    if (ec) {
        VSOMEIP_ERROR<< "routing_manager_stub::remove_from_pinged_clients "
        "setting expiry time of timer failed: " << ec.message();
    }
    pinged_clients_timer_.async_wait(
            std::bind(&routing_manager_stub::on_ping_timer_expired, this,
                      std::placeholders::_1));
}

bool routing_manager_stub::is_registered(client_t _client) const {
    std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
    return (routing_info_.find(_client) != routing_info_.end());
}

void routing_manager_stub::update_registration(client_t _client,
        registration_type_e _type,
        const boost::asio::ip::address &_address, port_t _port) {

    std::stringstream its_client;
    its_client << std::hex << std::setfill('0') << std::setw(4) << _client;

    if (_port > 0 && _port < ILLEGAL_PORT) {
        its_client << " @ " << _address.to_string() << ":" << std::dec << _port;
    }

    VSOMEIP_INFO << "Application/Client "
        << its_client.str()
        << " is "
        << (_type == registration_type_e::REGISTER ?
                "registering." : "deregistering.");

    if (_type != registration_type_e::REGISTER) {
        configuration_->get_policy_manager()->remove_client_to_sec_client_mapping(_client);
    } else {
        if (_port > 0 && _port < ILLEGAL_PORT)
            host_->add_guest(_client, _address, _port);
    }

    if (_type == registration_type_e::DEREGISTER) {
        host_->remove_guest(_client);

        // If we receive a DEREGISTER client command
        // the endpoint error handler is not longer needed
        // as the client is going down anyways.

        // Normally the handler is removed in "remove_local"
        // anyways, but as some time takes place until
        // the client DEREGISTER command is consumed
        // and therefore "remove_local" is finally called
        // it was possible the same client registers itself
        // again in very short time and then could "overtake"
        // the occurring error in the endpoint and was then
        // erroneously unregistered even that error has
        // nothing to do with the newly registered client.

        auto its_endpoint = host_->find_local(_client);
        if (its_endpoint) {
            its_endpoint->register_error_handler(nullptr);
        }
    }

    std::lock_guard<std::mutex> its_lock(client_registration_mutex_);
    pending_client_registrations_[_client].push_back(_type);
    client_registration_condition_.notify_one();

    if (_type != registration_type_e::REGISTER) {
        std::lock_guard<std::mutex> its_lock(used_client_ids_mutex_);
        used_client_ids_.erase(_client);
    }
}

client_t routing_manager_stub::get_client() const {
    return host_->get_client();
}

void routing_manager_stub::handle_credentials(const client_t _client, std::set<protocol::service> &_requests) {
    if (!_requests.size()) {
        return;
    }

    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);
    std::set<std::pair<uid_t, gid_t>> its_credentials;
    vsomeip_sec_client_t its_requester_sec_client;
    if (configuration_->get_policy_manager()->get_client_to_sec_client_mapping(_client, its_requester_sec_client)) {
        // determine credentials of offering clients using current routing info
        std::set<client_t> its_offering_clients;

        // search in local clients for the offering client
        for (auto request : _requests) {
            std::set<client_t> its_clients;
            its_clients = host_->find_local_clients(request.service_, request.instance_);
            for (auto its_client : its_clients) {
                its_offering_clients.insert(its_client);
            }
        }

        // search for UID / GID linked with the client ID that offers the requested services
        for (auto its_offering_client : its_offering_clients) {
            vsomeip_sec_client_t its_sec_client;
            if (configuration_->get_policy_manager()->get_client_to_sec_client_mapping(its_offering_client, its_sec_client)) {
                if (its_sec_client.port == VSOMEIP_SEC_PORT_UNUSED
                        && !utility::compare(its_sec_client, its_requester_sec_client)) {

                    its_credentials.insert(std::make_pair(
                            its_sec_client.user, its_sec_client.group));
                }
            }
        }

        // send credentials to clients
        if (!its_credentials.empty())
            send_client_credentials(_client, its_credentials);
    }
}

void routing_manager_stub::handle_requests(const client_t _client, std::set<protocol::service> &_requests) {

    if (_requests.empty())
        return;

    boost::asio::ip::address its_address;
    port_t its_port;

    std::vector<protocol::routing_info_entry> its_entries;
    std::lock_guard<std::mutex> its_guard(routing_info_mutex_);

    for (auto request : _requests) {
        service_requests_[_client][request.service_][request.instance_]
            = std::make_pair(request.major_, request.minor_);
        if (request.instance_ == ANY_INSTANCE) {
            std::set<client_t> its_clients = host_->find_local_clients(request.service_, request.instance_);
            // insert VSOMEIP_ROUTING_CLIENT to check whether service is remotely offered
            its_clients.insert(VSOMEIP_ROUTING_CLIENT);
            for (const client_t c : its_clients) {
                if (c != VSOMEIP_ROUTING_CLIENT &&
                        c != host_->get_client()) {
                    if (!is_connected(c, _client)) {
                        add_connection(c, _client);

                        protocol::routing_info_entry its_entry;
                        its_entry.set_type(protocol::routing_info_entry_type_e::RIE_ADD_CLIENT);
                        its_entry.set_client(_client);
                        if (host_->get_guest(_client, its_address, its_port)) {
                            its_entry.set_address(its_address);
                            its_entry.set_port(its_port);
                        }
                        if (_client == c) {
                            its_entries.emplace_back(its_entry);
                        } else {
                            send_client_routing_info(c, its_entry);
                        }
                    }
                }
                if (_client != VSOMEIP_ROUTING_CLIENT && _client != host_->get_client()) {
                    const auto found_client = routing_info_.find(c);
                    if (found_client != routing_info_.end()) {
                        const auto found_service = found_client->second.second.find(request.service_);
                        if (found_service != found_client->second.second.end()) {
                            for (auto instance : found_service->second) {
                                add_connection(_client, c);

                                protocol::routing_info_entry its_entry;
                                its_entry.set_type(protocol::routing_info_entry_type_e::RIE_ADD_SERVICE_INSTANCE);
                                its_entry.set_client(c);
                                if (host_->get_guest(c, its_address, its_port)) {
                                    its_entry.set_address(its_address);
                                    its_entry.set_port(its_port);
                                }
                                its_entry.add_service({ request.service_, instance.first,
                                        instance.second.first, instance.second.second });
                                its_entries.emplace_back(its_entry);
                            }
                        }
                    }
                }
            }
        } else {
            const client_t c = host_->find_local_client(request.service_, request.instance_);
            const auto found_client = routing_info_.find(c);
            if (found_client != routing_info_.end()) {
                const auto found_service = found_client->second.second.find(request.service_);
                if (found_service != found_client->second.second.end()) {
                    const auto found_instance = found_service->second.find(request.instance_);
                    if (found_instance != found_service->second.end()) {
                        if (c != VSOMEIP_ROUTING_CLIENT && c != host_->get_client()) {
                            if (!is_connected(c, _client)) {
                                add_connection(c, _client);

                                protocol::routing_info_entry its_entry;
                                its_entry.set_type(protocol::routing_info_entry_type_e::RIE_ADD_CLIENT);
                                its_entry.set_client(_client);
                                if (host_->get_guest(_client, its_address, its_port)) {
                                    its_entry.set_address(its_address);
                                    its_entry.set_port(its_port);
                                }
                                if (_client == c) {
                                    its_entries.emplace_back(its_entry);
                                } else {
                                    send_client_routing_info(c, its_entry);
                                }
                            }
                        }
                        if (_client != VSOMEIP_ROUTING_CLIENT && _client != host_->get_client()) {
                            add_connection(_client, c);

                            protocol::routing_info_entry its_entry;
                            its_entry.set_type(protocol::routing_info_entry_type_e::RIE_ADD_SERVICE_INSTANCE);
                            its_entry.set_client(c);
                            if (host_->get_guest(c, its_address, its_port)) {
                                its_entry.set_address(its_address);
                                its_entry.set_port(its_port);
                            }
                            its_entry.add_service({ request.service_, request.instance_,
                                    found_instance->second.first, found_instance->second.second });
                            its_entries.emplace_back(its_entry);
                        }
                    }
                }
            }
        }
    }

    if (!its_entries.empty())
        send_client_routing_info(_client, std::move(its_entries));
}

void routing_manager_stub::on_client_id_timer_expired(boost::system::error_code const &_error) {
    std::set<client_t> used_client_ids;
    {
        std::lock_guard<std::mutex> its_lock(used_client_ids_mutex_);
        used_client_ids = used_client_ids_;
        used_client_ids_.clear();
    }

    std::set<client_t> erroneous_clients;
    if (!_error) {
        std::lock_guard<std::mutex> its_lock(routing_info_mutex_);
        for (auto client : used_client_ids) {
            if (client != VSOMEIP_ROUTING_CLIENT && client != get_client()) {
                if (routing_info_.find(client) == routing_info_.end()) {
                    erroneous_clients.insert(client);
                }
            }
        }
    }
    for (auto client : erroneous_clients) {
        VSOMEIP_WARNING << "Releasing client identifier "
                << std::hex << std::setw(4) << std::setfill('0') << client << ". "
                << "Its corresponding application went offline while no "
                << "routing manager was running.";
        host_->handle_client_error(client);
    }
}

void routing_manager_stub::print_endpoint_status() const {
    if (local_receiver_) {
        local_receiver_->print_status();
    }
    if (root_) {
        root_->print_status();
    }
}

bool routing_manager_stub::send_provided_event_resend_request(
        client_t _client, pending_remote_offer_id_t _id) {

    std::shared_ptr<endpoint> its_endpoint = host_->find_local(_client);
    if (its_endpoint) {

        protocol::resend_provided_events_command its_command;
        its_command.set_client(VSOMEIP_ROUTING_CLIENT);
        its_command.set_remote_offer_id(_id);

        std::vector<byte_t> its_buffer;
        protocol::error_e its_error;
        its_command.serialize(its_buffer, its_error);

        if (its_error == protocol::error_e::ERROR_OK)
            return its_endpoint->send(&its_buffer[0], uint32_t(its_buffer.size()));
    } else {
        VSOMEIP_WARNING << __func__ << " Couldn't send provided event resend "
                "request to local client: 0x"
                << std::hex << std::setw(4) << std::setfill('0') << _client;
    }

    return false;
}

#ifndef VSOMEIP_DISABLE_SECURITY
bool routing_manager_stub::is_policy_cached(uid_t _uid) {
    {
        std::lock_guard<std::mutex> its_lock(updated_security_policies_mutex_);
        if (updated_security_policies_.find(_uid)
                != updated_security_policies_.end()) {
            VSOMEIP_INFO << __func__ << " Policy for UID: " << std::dec
                    << _uid << " was already updated before!";
            return true;
        } else {
            return false;
        }
    }
}

void routing_manager_stub::policy_cache_add(uid_t _uid, const std::shared_ptr<payload>& _payload) {
    // cache security policy payload for later distribution to new registering clients
    {
        std::lock_guard<std::mutex> its_lock(updated_security_policies_mutex_);
        updated_security_policies_[_uid] = _payload;
    }
}

void routing_manager_stub::policy_cache_remove(uid_t _uid) {
    {
        std::lock_guard<std::mutex> its_lock(updated_security_policies_mutex_);
        updated_security_policies_.erase(_uid);
    }
}

bool routing_manager_stub::send_update_security_policy_request(client_t _client, pending_security_update_id_t _update_id,
                                                               uid_t _uid, const std::shared_ptr<payload>& _payload) {
    (void)_uid;

    std::shared_ptr<endpoint> its_endpoint = host_->find_local(_client);
    if (its_endpoint) {
        std::vector<byte_t> its_command;
        // command
        its_command.push_back(byte_t(protocol::id_e::UPDATE_SECURITY_POLICY_ID));

        // version
        its_command.push_back(0x00);
        its_command.push_back(0x00);

        // client ID
        for (uint32_t i = 0; i < sizeof(client_t); ++i) {
             its_command.push_back(
                     reinterpret_cast<const byte_t*>(&_client)[i]);
        }
        // security update id length + payload length including gid and uid
        std::uint32_t its_size = uint32_t(sizeof(pending_security_update_id_t) + _payload->get_length());
        for (uint32_t i = 0; i < sizeof(its_size); ++i) {
             its_command.push_back(
                     reinterpret_cast<const byte_t*>(&its_size)[i]);
        }
        // ID of update request
        for (uint32_t i = 0; i < sizeof(pending_security_update_id_t); ++i) {
             its_command.push_back(
                     reinterpret_cast<const byte_t*>(&_update_id)[i]);
        }
        // payload
        for (uint32_t i = 0; i < _payload->get_length(); ++i) {
             its_command.push_back(_payload->get_data()[i]);
        }

        return its_endpoint->send(its_command.data(), uint32_t(its_command.size()));
    } else {
        return false;
    }
}

bool routing_manager_stub::send_cached_security_policies(client_t _client) {

    std::shared_ptr<endpoint> its_endpoint = host_->find_local(_client);
    if (its_endpoint) {


        std::lock_guard<std::mutex> its_lock(updated_security_policies_mutex_);
        if (!updated_security_policies_.empty()) {

            VSOMEIP_INFO << __func__ << " Distributing ["
                    << std::dec << updated_security_policies_.size()
                    << "] security policy updates to registering client: "
                    << std::hex << _client;

            protocol::distribute_security_policies_command its_command;
            its_command.set_client(get_client());
            its_command.set_payloads(updated_security_policies_);

            std::vector<byte_t> its_buffer;
            protocol::error_e its_error;
            its_command.serialize(its_buffer, its_error);

            if (its_error == protocol::error_e::ERROR_OK)
                return its_endpoint->send(its_buffer.data(), uint32_t(its_buffer.size()));

            VSOMEIP_ERROR << __func__
                    << ": serializing distribute security policies ("
                    << static_cast<int>(its_error)
                    << ")";
        }
    } else
        VSOMEIP_WARNING << __func__
            << ": could not send cached security policies to registering client: 0x"
            << std::hex << std::setw(4) << std::setfill('0') << _client;

    return false;
}

bool routing_manager_stub::send_remove_security_policy_request(
        client_t _client, pending_security_update_id_t _update_id,
        uid_t _uid, gid_t _gid) {

    protocol::remove_security_policy_command its_command;
    its_command.set_client(_client);
    its_command.set_update_id(_update_id);
    its_command.set_uid(_uid);
    its_command.set_gid(_gid);

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK) {
        std::shared_ptr<endpoint> its_endpoint = host_->find_local(_client);
        if (its_endpoint)
            return its_endpoint->send(&its_buffer[0], uint32_t(its_buffer.size()));
        else
            VSOMEIP_ERROR << __func__
                << ": cannot find local client endpoint for client "
                << std::hex << std::setw(4) << std::setfill('0')
                << _client;
    } else
        VSOMEIP_ERROR << __func__
            << ": remove security policy command serialization failed ("
            << std::dec << static_cast<int>(its_error)
            << ")";

    return false;

}

bool
routing_manager_stub::add_requester_policies(uid_t _uid, gid_t _gid,
        const std::set<std::shared_ptr<policy> > &_policies) {

    std::lock_guard<std::mutex> its_lock(requester_policies_mutex_);
    auto found_uid = requester_policies_.find(_uid);
    if (found_uid != requester_policies_.end()) {
        auto found_gid = found_uid->second.find(_gid);
        if (found_gid != found_uid->second.end()) {
            found_gid->second.insert(_policies.begin(), _policies.end());
        } else {
            found_uid->second[_gid] = _policies;
        }
    } else {
        requester_policies_[_uid][_gid] = _policies;
    }

    // Check whether clients with uid/gid are already registered.
    // If yes, update their policy
    std::unordered_set<client_t> its_clients;
    configuration_->get_policy_manager()->get_clients(_uid, _gid, its_clients);

    if (!its_clients.empty())
        return send_requester_policies(its_clients, _policies);

    return true;
}

void
routing_manager_stub::remove_requester_policies(uid_t _uid, gid_t _gid) {

    std::lock_guard<std::mutex> its_lock(requester_policies_mutex_);
    auto found_uid = requester_policies_.find(_uid);
    if (found_uid != requester_policies_.end()) {
        found_uid->second.erase(_gid);
        if (found_uid->second.empty())
            requester_policies_.erase(_uid);
    }
}

void
routing_manager_stub::get_requester_policies(uid_t _uid, gid_t _gid,
        std::set<std::shared_ptr<policy> > &_policies) const {

    std::lock_guard<std::mutex> its_lock(requester_policies_mutex_);
    auto found_uid = requester_policies_.find(_uid);
    if (found_uid != requester_policies_.end()) {
        auto found_gid = found_uid->second.find(_gid);
        if (found_gid != found_uid->second.end())
            _policies = found_gid->second;
    }
}

void
routing_manager_stub::add_pending_security_update_handler(
        pending_security_update_id_t _id, const security_update_handler_t &_handler) {

    std::lock_guard<std::recursive_mutex> its_lock(security_update_handlers_mutex_);
    security_update_handlers_[_id] = _handler;
}

void
routing_manager_stub::add_pending_security_update_timer(
        pending_security_update_id_t _id) {

    std::shared_ptr<boost::asio::steady_timer> its_timer
        = std::make_shared<boost::asio::steady_timer>(io_);

    boost::system::error_code ec;
    its_timer->expires_from_now(std::chrono::milliseconds(3000), ec);
    if (!ec) {
        its_timer->async_wait(
                std::bind(
                        &routing_manager_stub::on_security_update_timeout,
                        shared_from_this(),
                        std::placeholders::_1, _id, its_timer));
    } else {
        VSOMEIP_ERROR << __func__
                << "[" << std::dec << _id << "]: timer creation: "
                << ec.message();
    }
    std::lock_guard<std::mutex> its_lock(security_update_timers_mutex_);
    security_update_timers_[_id] = its_timer;
}

bool
routing_manager_stub::send_requester_policies(const std::unordered_set<client_t> &_clients,
        const std::set<std::shared_ptr<policy> > &_policies) {

    pending_security_update_id_t its_policy_id;

    // serialize the policies and send them...
    for (const auto &p : _policies) {
        std::vector<byte_t> its_policy_data;
        if (p->serialize(its_policy_data)) {
            std::vector<byte_t> its_message;
            its_message.push_back(byte_t(protocol::id_e::UPDATE_SECURITY_POLICY_INT_ID));

            // version
            its_message.push_back(0);
            its_message.push_back(0);

            // client identifier
            its_message.push_back(0);
            its_message.push_back(0);

            uint32_t its_policy_size = static_cast<uint32_t>(its_policy_data.size() + sizeof(uint32_t));

            uint8_t new_its_policy_size[4] = {0};
            bithelper::write_uint32_le(its_policy_size, new_its_policy_size);
            its_message.insert(its_message.end(), new_its_policy_size, new_its_policy_size + sizeof(new_its_policy_size));

            its_policy_id = pending_security_update_add(_clients);
            uint8_t new_its_policy_id[4] = {0};
            bithelper::write_uint32_le(its_policy_id, new_its_policy_id);
            its_message.insert(its_message.end(), new_its_policy_id, new_its_policy_id + sizeof(new_its_policy_id));
            its_message.insert(its_message.end(), its_policy_data.begin(), its_policy_data.end());

            for (const auto c : _clients) {
                std::shared_ptr<endpoint> its_endpoint = host_->find_local(c);
                if (its_endpoint)
                    its_endpoint->send(&its_message[0], static_cast<uint32_t>(its_message.size()));
            }
        }
    }

    return true;
}

void routing_manager_stub::on_security_update_timeout(
        const boost::system::error_code& _error,
        pending_security_update_id_t _id,
        std::shared_ptr<boost::asio::steady_timer> _timer) {
    (void)_timer;
    if (_error) {
        // timer was cancelled
        return;
    }
    security_update_state_e its_state = security_update_state_e::SU_UNKNOWN_USER_ID;
    std::unordered_set<client_t> its_missing_clients = pending_security_update_get(_id);
    {
        // erase timer
        std::lock_guard<std::mutex> its_lock(security_update_timers_mutex_);
        security_update_timers_.erase(_id);
    }
    {
        //  print missing responses and check if some clients did not respond because they already disconnected
        if (!its_missing_clients.empty()) {
            for (auto its_client : its_missing_clients) {
                VSOMEIP_INFO << __func__ << ": Client 0x" << std::hex << its_client
                        << " did not respond to the policy update / removal with ID: 0x" << std::hex << _id;
                if (!host_->find_local(its_client)) {
                    VSOMEIP_INFO << __func__ << ": Client 0x" << std::hex << its_client
                            << " is not connected anymore, do not expect answer for policy update / removal with ID: 0x"
                            << std::hex << _id;
                    pending_security_update_remove(_id, its_client);
                }
            }
        }

        its_missing_clients = pending_security_update_get(_id);
        if (its_missing_clients.empty()) {
            VSOMEIP_INFO << __func__ << ": Received all responses for "
                    "security update/removal ID: 0x" << std::hex << _id;
            its_state = security_update_state_e::SU_SUCCESS;
        }
        {
            // erase pending security update
            std::lock_guard<std::mutex> its_lock(pending_security_updates_mutex_);
            pending_security_updates_.erase(_id);
        }

        // call handler with error on timeout or with SUCCESS if missing clients are not connected
        std::lock_guard<std::recursive_mutex> its_lock(security_update_handlers_mutex_);
        const auto found_handler = security_update_handlers_.find(_id);
        if (found_handler != security_update_handlers_.end()) {
            found_handler->second(its_state);
            security_update_handlers_.erase(found_handler);
        } else {
            VSOMEIP_WARNING << __func__ << ": Callback not found for security update / removal with ID: 0x"
                    << std::hex << _id;
        }
    }
}

bool routing_manager_stub::update_security_policy_configuration(
        uid_t _uid, gid_t _gid,
        const std::shared_ptr<policy> &_policy,
        const std::shared_ptr<payload> &_payload,
        const security_update_handler_t &_handler) {

    bool ret(true);

    // cache security policy payload for later distribution to new registering clients
    policy_cache_add(_uid, _payload);

    // update security policy from configuration
    configuration_->get_policy_manager()->update_security_policy(_uid, _gid, _policy);

    // Build requester policies for the services offered by the new policy
    std::set<std::shared_ptr<policy> > its_requesters;
    configuration_->get_policy_manager()->get_requester_policies(_policy, its_requesters);

    // and add them to the requester policy cache
    add_requester_policies(_uid, _gid, its_requesters);

    // determine currently connected clients
    std::unordered_set<client_t> its_clients_to_inform;
    auto its_epm = host_->get_endpoint_manager();
    if (its_epm)
        its_clients_to_inform = its_epm->get_connected_clients();

    // add handler
    pending_security_update_id_t its_id;
    if (!its_clients_to_inform.empty()) {
        its_id = pending_security_update_add(its_clients_to_inform);

        add_pending_security_update_handler(its_id, _handler);
        add_pending_security_update_timer(its_id);

        // trigger all currently connected clients to update the security policy
        uint32_t sent_counter(0);
        uint32_t its_tranche =
                uint32_t(its_clients_to_inform.size() >= 10 ? (its_clients_to_inform.size() / 10) : 1);
        VSOMEIP_INFO << __func__ << ": Informing [" << std::dec << its_clients_to_inform.size()
                << "] currently connected clients about policy update for UID: "
                << std::dec << _uid << " with update ID: 0x" << std::hex << its_id;
        for (auto its_client : its_clients_to_inform) {
            if (!send_update_security_policy_request(its_client, its_id, _uid, _payload)) {
                VSOMEIP_INFO << __func__ << ": Couldn't send update security policy "
                                        << std::hex << std::setfill('0')
                                        << "request to client 0x" << std::setw(4) << its_client
                                        << " policy UID: " << std::setw(4) << _uid
                                        << " GID: " << std::setw(4) << _gid
                                        << " with update ID: 0x" << its_id
                                        << " as client already disconnected";
                // remove client from expected answer list
                pending_security_update_remove(its_id, its_client);
            }
            sent_counter++;
            // Prevent burst
            if (sent_counter % its_tranche == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    } else {
        // if routing manager has no client call the handler directly
        _handler(security_update_state_e::SU_SUCCESS);
    }

    return ret;
}

bool routing_manager_stub::remove_security_policy_configuration(
        uid_t _uid, gid_t _gid, const security_update_handler_t &_handler) {

    bool ret(true);

    // remove security policy from configuration (only if there was a updateACL call before)
    if (is_policy_cached(_uid)) {
        if (!configuration_->get_policy_manager()->remove_security_policy(_uid, _gid)) {
            _handler(security_update_state_e::SU_UNKNOWN_USER_ID);
            ret = false;
        } else {
            // remove policy from cache to prevent sending it to registering clients
            policy_cache_remove(_uid);

            // add handler
            pending_security_update_id_t its_id;

            // determine currently connected clients
            std::unordered_set<client_t> its_clients_to_inform;
            auto its_epm = host_->get_endpoint_manager();
            if (its_epm)
                its_clients_to_inform = its_epm->get_connected_clients();

            if (!its_clients_to_inform.empty()) {
                its_id = pending_security_update_add(its_clients_to_inform);

                add_pending_security_update_handler(its_id, _handler);
                add_pending_security_update_timer(its_id);

                // trigger all clients to remove the security policy
                uint32_t sent_counter(0);
                uint32_t its_tranche =
                        uint32_t(its_clients_to_inform.size() >= 10 ? (its_clients_to_inform.size() / 10) : 1);
                VSOMEIP_INFO << __func__ << ": Informing [" << std::dec << its_clients_to_inform.size()
                        << "] currently connected clients about policy removal for UID: "
                        << std::dec << _uid << " with update ID: " << its_id;
                for (auto its_client : its_clients_to_inform) {
                    if (!send_remove_security_policy_request(its_client, its_id, _uid, _gid)) {
                        VSOMEIP_INFO << __func__ << ": Couldn't send remove security policy "
                                                << std::hex << std::setfill('0')
                                                << "request to client 0x" << std::setw(4) << its_client
                                                << " policy UID: " << std::setw(4) << _uid
                                                << " GID: " << std::setw(4) << _gid
                                                << " with update ID: 0x" << its_id
                                                << " as client already disconnected";
                        // remove client from expected answer list
                        pending_security_update_remove(its_id, its_client);
                    }
                    sent_counter++;
                    // Prevent burst
                    if (sent_counter % its_tranche == 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
            } else {
                // if routing manager has no client call the handler directly
                _handler(security_update_state_e::SU_SUCCESS);
            }
        }
    }
    else {
        _handler(security_update_state_e::SU_UNKNOWN_USER_ID);
        ret = false;
    }
    return ret;
}

pending_security_update_id_t routing_manager_stub::pending_security_update_add(
        const std::unordered_set<client_t>& _clients) {
    std::lock_guard<std::mutex> its_lock(pending_security_updates_mutex_);
    if (++pending_security_update_id_ == 0) {
        pending_security_update_id_++;
    }
    pending_security_updates_[pending_security_update_id_] = _clients;

    return pending_security_update_id_;
}

std::unordered_set<client_t> routing_manager_stub::pending_security_update_get(
        pending_security_update_id_t _id) {
    std::lock_guard<std::mutex> its_lock(pending_security_updates_mutex_);
    std::unordered_set<client_t> its_missing_clients;
    auto found_si = pending_security_updates_.find(_id);
    if (found_si != pending_security_updates_.end()) {
        its_missing_clients = pending_security_updates_[_id];
    }
    return its_missing_clients;
}

bool routing_manager_stub::pending_security_update_remove(
        pending_security_update_id_t _id, client_t _client) {
    std::lock_guard<std::mutex> its_lock(pending_security_updates_mutex_);
    auto found_si = pending_security_updates_.find(_id);
    if (found_si != pending_security_updates_.end()) {
        if (found_si->second.erase(_client)) {
            return true;
        }
    }
    return false;
}

bool routing_manager_stub::is_pending_security_update_finished(
        pending_security_update_id_t _id) {
    std::lock_guard<std::mutex> its_lock(pending_security_updates_mutex_);
    bool ret(false);
    auto found_si = pending_security_updates_.find(_id);
    if (found_si != pending_security_updates_.end()) {
        if (!found_si->second.size()) {
            ret = true;
        }
    }
    if (ret) {
        pending_security_updates_.erase(_id);
    }
    return ret;
}

void routing_manager_stub::on_security_update_response(
        pending_security_update_id_t _id, client_t _client) {
    if (pending_security_update_remove(_id, _client)) {
        if (is_pending_security_update_finished(_id)) {
            // cancel timeout timer
            {
                std::lock_guard<std::mutex> its_lock(security_update_timers_mutex_);
                auto found_timer = security_update_timers_.find(_id);
                if (found_timer != security_update_timers_.end()) {
                    boost::system::error_code ec;
                    found_timer->second->cancel(ec);
                    security_update_timers_.erase(found_timer);
                } else {
                    VSOMEIP_WARNING << __func__ << ": Received all responses "
                            "for security update/removal ID: 0x"
                            << std::hex << _id << " but timeout already happened";
                }
            }

            // call handler
            {
                std::lock_guard<std::recursive_mutex> its_lock(security_update_handlers_mutex_);
                auto found_handler = security_update_handlers_.find(_id);
                if (found_handler != security_update_handlers_.end()) {
                    found_handler->second(security_update_state_e::SU_SUCCESS);
                    security_update_handlers_.erase(found_handler);
                    VSOMEIP_INFO << __func__ << ": Received all responses for "
                            "security update/removal ID: 0x" << std::hex << _id;
                } else {
                    VSOMEIP_WARNING << __func__ << ": Received all responses "
                            "for security update/removal ID: 0x"
                            << std::hex << _id << " but didn't find handler";
                }
            }
        }
    }
}
#endif // !VSOMEIP_DISABLE_SECURITY

void routing_manager_stub::send_suspend() const {

    protocol::suspend_command its_command;

    std::vector<byte_t> its_buffer;
    protocol::error_e its_error;
    its_command.serialize(its_buffer, its_error);

    if (its_error == protocol::error_e::ERROR_OK)
        broadcast(its_buffer);
    else
        VSOMEIP_ERROR << __func__
            << ": suspend command serialization failed ("
            << std::dec << int(its_error) << ")";
}

routing_state_e routing_manager_stub::get_routing_state() {
    return host_->get_routing_state();
}

void
routing_manager_stub::remove_subscriptions(port_t _local_port,
        const boost::asio::ip::address &_remote_address,
        port_t _remote_port) {

    (void)_local_port;
    (void)_remote_address;
    (void)_remote_port;
    // dummy method to implement routing_host interface
}

} // namespace vsomeip_v3
