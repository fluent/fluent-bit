// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <map>
#include <algorithm>
#include <unordered_set>
#include <atomic>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "subscribe_notify_one_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class subscribe_notify_one_test_service : public vsomeip_utilities::base_logger {
public:
    subscribe_notify_one_test_service(struct subscribe_notify_one_test::service_info _service_info, vsomeip::reliability_type_e _reliability_type) :
            vsomeip_utilities::base_logger("SNOS", "SUBSCRIBE NOTIFY ONE TEST SERVICE"),
            service_info_(_service_info),
            app_(vsomeip::runtime::get()->create_application()),
            wait_until_registered_(true),
            wait_until_other_services_available_(true),
            wait_until_notified_from_other_services_(true),
            offer_thread_(std::bind(&subscribe_notify_one_test_service::run, this)),
            wait_for_stop_(true),
            stop_thread_(std::bind(&subscribe_notify_one_test_service::wait_for_stop, this)),
            wait_for_notify_(true),
            notify_thread_(std::bind(&subscribe_notify_one_test_service::notify_one, this)),
            subscription_state_handler_called_(0),
            subscription_error_occured_(false),
            reliability_type_(_reliability_type) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&subscribe_notify_one_test_service::on_state, this,
                        std::placeholders::_1));

        // offer event
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(service_info_.eventgroup_id);
        app_->offer_event(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_eventgroups, vsomeip::event_type_e::ET_SELECTIVE_EVENT,
                std::chrono::milliseconds::zero(), false, true, nullptr,
                reliability_type_);

        app_->register_message_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.method_id,
                std::bind(&subscribe_notify_one_test_service::on_request, this,
                        std::placeholders::_1));

        // register subscription handler to detect whether or not all other
        // other services have subscribed
        app_->register_subscription_handler(service_info_.service_id,
                service_info_.instance_id, service_info_.eventgroup_id,
                std::bind(&subscribe_notify_one_test_service::on_subscription, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3, std::placeholders::_4));

        // register availability for all other services and request their event.
        for(const auto& i : subscribe_notify_one_test::service_infos) {
            if ((i.service_id == service_info_.service_id
                    && i.instance_id == service_info_.instance_id)
                    || (i.service_id == 0xFFFF && i.instance_id == 0xFFFF)) {
                continue;
            }
            app_->register_message_handler(i.service_id,
                    i.instance_id, vsomeip::ANY_METHOD,
                    std::bind(&subscribe_notify_one_test_service::on_message, this,
                            std::placeholders::_1));
            app_->register_availability_handler(i.service_id, i.instance_id,
                    std::bind(&subscribe_notify_one_test_service::on_availability, this,
                            std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3));

            app_->request_service(i.service_id, i.instance_id, vsomeip::DEFAULT_MAJOR, vsomeip::DEFAULT_MINOR);

            auto handler = std::bind(&subscribe_notify_one_test_service::on_subscription_state_change, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
            app_->register_subscription_status_handler(i.service_id, i.instance_id, i.eventgroup_id, vsomeip::ANY_EVENT, handler);
            app_->register_subscription_status_handler(vsomeip::ANY_SERVICE, i.instance_id, i.eventgroup_id, vsomeip::ANY_EVENT, handler);
            app_->register_subscription_status_handler(i.service_id, vsomeip::ANY_INSTANCE, i.eventgroup_id, vsomeip::ANY_EVENT, handler);
            app_->register_subscription_status_handler(vsomeip::ANY_SERVICE, vsomeip::ANY_INSTANCE, i.eventgroup_id, vsomeip::ANY_EVENT, handler);

            std::set<vsomeip::eventgroup_t> its_eventgroups;
            its_eventgroups.insert(i.eventgroup_id);
            app_->request_event(i.service_id, i.instance_id, i.event_id, its_eventgroups, vsomeip::event_type_e::ET_SELECTIVE_EVENT, reliability_type_);

            other_services_available_[std::make_pair(i.service_id, i.instance_id)] = false;
            other_services_received_notification_[std::make_pair(i.service_id, i.method_id)] = 0;
        }

        app_->start();
    }

    ~subscribe_notify_one_test_service() {
        offer_thread_.join();
        stop_thread_.join();
    }

    void offer() {
        app_->offer_service(service_info_.service_id, service_info_.instance_id);
    }

    void stop_offer() {
        app_->stop_offer_event(service_info_.service_id, service_info_.instance_id, service_info_.event_id);
        app_->stop_offer_service(service_info_.service_id, service_info_.instance_id);
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_DEBUG << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_registered_ = false;
            condition_.notify_one();
        }
    }

    void on_availability(vsomeip::service_t _service,
                         vsomeip::instance_t _instance, bool _is_available) {
        if(_is_available) {
            auto its_service = other_services_available_.find(std::make_pair(_service, _instance));
            if(its_service != other_services_available_.end()) {
                if(its_service->second != _is_available) {
                its_service->second = true;
                VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << service_info_.service_id << "] Service ["
                << std::setw(4) << std::setfill('0') << std::hex << _service << "." << _instance
                << "] is available.";

                }
            }

            if(std::all_of(other_services_available_.cbegin(),
                           other_services_available_.cend(),
                           [](const std::map<std::pair<vsomeip::service_t,
                                   vsomeip::instance_t>, bool>::value_type& v) {
                                return v.second;})) {
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_until_other_services_available_ = false;
                condition_.notify_one();
            }
        }
    }

    void on_subscription_state_change(const vsomeip::service_t _service, const vsomeip::instance_t _instance,
            const vsomeip::eventgroup_t _eventgroup, const vsomeip::event_t _event, const uint16_t _error) {
        (void)_service;
        (void)_instance;
        (void)_eventgroup;
        (void)_event;
        if (!_error) {
            subscription_state_handler_called_++;
        } else {
            subscription_error_occured_ = true;
            VSOMEIP_ERROR << std::hex << app_->get_client()
                    << " : on_subscription_state_change: for service " << std::hex
                    << _service << " received a subscription error!";
        }

    }

    bool on_subscription(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid, bool _subscribed) {
        (void)_uid;
        (void)_gid;
        std::lock_guard<std::mutex> its_subscribers_lock(subscribers_mutex_);

        // check if all other services have subscribed:
        // -1 for placeholder in array and -1 for the service itself
        if (subscribers_.size() == subscribe_notify_one_test::service_infos.size() - 2) {
            return true;
        }

        if (_subscribed) {
            subscribers_.insert(_client);
        } else {
            subscribers_.erase(_client);
        }

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] " << "Client: " << _client
                << " subscribed, now have " << std::dec << subscribers_.size()
                << " subscribers. Expecting " << std::dec
                << subscribe_notify_one_test::service_infos.size() - 2;

        if (subscribers_.size() == subscribe_notify_one_test::service_infos.size() - 2)
        {
            // notify the notify thread to start sending out notifications
            std::lock_guard<std::mutex> its_lock(notify_mutex_);
            wait_for_notify_ = false;
            notify_condition_.notify_one();
        }
        return true;
    }

    void on_request(const std::shared_ptr<vsomeip::message> &_message) {
        if(_message->get_message_type() == vsomeip::message_type_e::MT_REQUEST) {
            VSOMEIP_DEBUG << "Received a request with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _message->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_session() << "]";
            std::shared_ptr<vsomeip::message> its_response = vsomeip::runtime::get()
            ->create_response(_message);
            app_->send(its_response);
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        if (_message->get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION) {

            other_services_received_notification_[std::make_pair(_message->get_service(),
                                                             _message->get_method())]++;

            VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
            << service_info_.service_id << "] "
            << "Received a notification with Client/Session [" << std::setw(4)
            << std::setfill('0') << std::hex << _message->get_client() << "/"
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_session() << "] from Service/Method ["
            << std::setw(4) << std::setfill('0') << std::hex
            << _message->get_service() << "/" << std::setw(4) << std::setfill('0')
            << std::hex << _message->get_method() << "] (now have: "
            << std::dec << other_services_received_notification_[std::make_pair(_message->get_service(),
                                                                    _message->get_method())] << ")";

            if (all_notifications_received()) {
                std::lock_guard<std::mutex> its_lock(stop_mutex_);
                wait_for_stop_ = false;
                stop_condition_.notify_one();
            }
        }
    }

    bool all_notifications_received() {
        return std::all_of(
                other_services_received_notification_.cbegin(),
                other_services_received_notification_.cend(),
                [&](const std::map<std::pair<vsomeip::service_t,
                        vsomeip::method_t>, std::uint32_t>::value_type& v)
                {
                    return v.second == subscribe_notify_one_test::notifications_to_send;
                }
        );
    }

    bool all_notifications_received_tcp_and_udp() {
        std::uint32_t received_twice(0);
        std::uint32_t received_normal(0);
        for(const auto &v : other_services_received_notification_) {
            if (v.second == subscribe_notify_one_test::notifications_to_send * 2) {
                received_twice++;
            } else if(v.second == subscribe_notify_one_test::notifications_to_send) {
                received_normal++;
            }
        }

        if(   received_twice == (subscribe_notify_one_test::service_infos.size() - 1) / 2
           && received_normal == (subscribe_notify_one_test::service_infos.size() - 1) / 2 - 1) {
            // routing manager stub receives the notification
            // - twice from external nodes
            // - and normal from all internal nodes
            VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << service_info_.service_id << "] "
                        << "Received notifications:"
                        << " Normal: " << received_normal
                        << " Twice: " << received_twice;
            return true;
        }
        return false;
    }

    void run() {
        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Running";
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_until_registered_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Offering";
        offer();


        while (wait_until_other_services_available_) {
            condition_.wait(its_lock);
        }

        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id << "] Subscribing";
        // subscribe to events of other services
        uint32_t subscribe_count = 0;
        for(const subscribe_notify_one_test::service_info& i: subscribe_notify_one_test::service_infos) {
            if ((i.service_id == service_info_.service_id
                            && i.instance_id == service_info_.instance_id)
                    || (i.service_id == 0xFFFF && i.instance_id == 0xFFFF)) {
                continue;
            }

            ++subscribe_count;
            app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                            vsomeip::DEFAULT_MAJOR);

            VSOMEIP_DEBUG << "[" << std::hex << service_info_.service_id
            << "] subscribing to Service/Instance/Eventgroup ["
            << std::setw(4) << std::setfill('0') << std::hex << i.service_id << "/"
            << std::setw(4) << std::setfill('0') << std::hex << i.instance_id
            << "/" << std::setw(4) << std::setfill('0') << std::hex << i.eventgroup_id << "]";

        }

        while (wait_until_notified_from_other_services_) {
            condition_.wait(its_lock);
        }

        // It is possible that we run in the case a subscription is NACKED
        // due to TCP endpoint not completely connected when subscription
        // is processed in the server - due to resubscribing the error handler
        // count may differ from expected value, but its not a real but as
        // the subscription takes places anyways and all events will be received.
        if (!subscription_error_occured_) {
            // 4 * subscribe count cause we installed three additional wild-card handlers
            ASSERT_EQ(subscribe_count * 4, subscription_state_handler_called_);
        } else {
            VSOMEIP_ERROR << "Subscription state handler check skipped: CallCount="
                    << std::dec << subscription_state_handler_called_;
        }
    }

    void notify_one() {
        std::unique_lock<std::mutex> its_lock(notify_mutex_);
        while(wait_for_notify_) {
            notify_condition_.wait(its_lock);
        }

        // sleep a while before starting to notify this is necessary as it's not
        // possible to detect if _all_ clients on the remote side have
        // successfully subscribed as we only receive once subscription per
        // remote node no matter how many clients subscribed to this eventgroup
        // on the remote node
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        for(uint32_t i = 0; i < subscribe_notify_one_test::notifications_to_send; i++) {
            std::shared_ptr<vsomeip::payload> its_payload =
                    vsomeip::runtime::get()->create_payload();

            vsomeip::byte_t its_data[10] = {0};
            for (uint32_t j = 0; j < i+1; ++j) {
                its_data[j] = static_cast<uint8_t>(j);
            }
            its_payload->set_data(its_data, i+1);

            for (vsomeip::client_t client : subscribers_) {
                VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                    << service_info_.service_id << "] Notifying client: "
                    << client << " : " << i+1;
                app_->notify_one(service_info_.service_id, service_info_.instance_id,
                        service_info_.event_id, its_payload, client);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void wait_for_stop() {
        std::unique_lock<std::mutex> its_lock(stop_mutex_);
        while (wait_for_stop_) {
            stop_condition_.wait(its_lock);
        }
        VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << service_info_.service_id
                << "] Received notifications from all other services, going down";

        // wait until all notifications have been sent out
        notify_thread_.join();

        // let offer thread exit
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_until_notified_from_other_services_ = false;
            condition_.notify_one();
        }

        stop_offer();

        // ensure that the service which hosts the routing doesn't exit to early
        if (app_->is_routing()) {
            for (const auto& i : subscribe_notify_one_test::service_infos) {
                if ((i.service_id == service_info_.service_id
                                && i.instance_id == service_info_.instance_id)
                        || (i.service_id == 0xFFFF && i.instance_id == 0xFFFF)) {
                    continue;
                }
                while (app_->is_available(i.service_id, i.instance_id,
                        vsomeip::ANY_MAJOR, vsomeip::ANY_MINOR)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
        }

        for(const auto& i : subscribe_notify_one_test::service_infos) {
            if ((i.service_id == service_info_.service_id
                    && i.instance_id == service_info_.instance_id)
                    || (i.service_id == 0xFFFF && i.instance_id == 0xFFFF)) {
                continue;
            }
            app_->unregister_subscription_status_handler(i.service_id, i.instance_id,
                    i.eventgroup_id, vsomeip::ANY_EVENT);
            app_->unsubscribe(i.service_id, i.instance_id, i.eventgroup_id);
            app_->release_event(i.service_id, i.instance_id, i.event_id);
            app_->release_service(i.service_id, i.instance_id);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        app_->clear_all_handler();
        app_->stop();
    }

private:
    subscribe_notify_one_test::service_info service_info_;
    std::shared_ptr<vsomeip::application> app_;
    std::map<std::pair<vsomeip::service_t, vsomeip::instance_t>, bool> other_services_available_;
    std::map<std::pair<vsomeip::service_t, vsomeip::method_t>, std::uint32_t> other_services_received_notification_;

    bool wait_until_registered_;
    bool wait_until_other_services_available_;
    bool wait_until_notified_from_other_services_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::thread offer_thread_;

    bool wait_for_stop_;
    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;
    std::thread stop_thread_;

    bool wait_for_notify_;
    std::mutex notify_mutex_;
    std::condition_variable notify_condition_;
    std::thread notify_thread_;

    std::unordered_set<vsomeip::client_t> subscribers_;
    std::atomic<uint32_t> subscription_state_handler_called_;
    std::atomic<bool> subscription_error_occured_;

    std::mutex subscribers_mutex_;
    vsomeip::reliability_type_e reliability_type_;
};

static unsigned long service_number;
vsomeip::reliability_type_e reliability_type = vsomeip::reliability_type_e::RT_UNKNOWN;


TEST(someip_subscribe_notify_one_test, send_ten_notifications_to_service)
{
    subscribe_notify_one_test_service its_sample(
            subscribe_notify_one_test::service_infos[service_number],
            reliability_type);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 3) {
        std::cerr << "Please specify a service number and event reliability type, like: " << argv[0] << " 2 UDP" << std::endl;
        std::cerr << "Valid service numbers are in the range of [1,6]" << std::endl;
        std::cerr << "Valid service reliability types are [UDP, TCP, TCP_AND_UDP]" << std::endl;

        return 1;
    }

    service_number = std::stoul(std::string(argv[1]), nullptr);

    if (std::string("TCP")== std::string(argv[2])) {
        reliability_type = vsomeip::reliability_type_e::RT_RELIABLE;
    } else if (std::string("UDP")== std::string(argv[2])) {
        reliability_type = vsomeip::reliability_type_e::RT_UNRELIABLE;
    } else if (std::string("TCP_AND_UDP")== std::string(argv[2])) {
        reliability_type = vsomeip::reliability_type_e::RT_BOTH;
    }

    return RUN_ALL_TESTS();
}
#endif
