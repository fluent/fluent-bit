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
#include <atomic>

#include <gtest/gtest.h>

#if defined(__linux__) || defined(ANDROID)
#include <signal.h>
#endif

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "initial_event_test_globals.hpp"

class initial_event_test_client;
static initial_event_test_client* the_client;
extern "C" void signal_handler(int _signum);

class initial_event_test_client {
public:
    initial_event_test_client(int _client_number,
                              bool _service_offered_tcp_and_udp,
                              std::array<initial_event_test::service_info, 7> _service_infos,
                              bool _subscribe_on_available, std::uint32_t _events_to_subscribe,
                              bool _initial_event_strict_checking,
                              bool _dont_exit, bool _subscribe_only_one,
                              vsomeip::reliability_type_e _reliability_type,
                              bool _client_subscribes_twice) :
            client_number_(_client_number),
            service_infos_(_service_infos),
            service_offered_tcp_and_udp_(_service_offered_tcp_and_udp),
            app_(vsomeip::runtime::get()->create_application()),
            wait_until_registered_(true),
            wait_for_stop_(true),
            is_first(true),
            subscribe_on_available_(_subscribe_on_available),
            events_to_subscribe_(_events_to_subscribe),
            initial_event_strict_checking_(_initial_event_strict_checking),
            dont_exit_(_dont_exit),
            subscribe_only_one_(_subscribe_only_one),
            stop_thread_(&initial_event_test_client::wait_for_stop, this),
            wait_for_signal_handler_registration_(true),
            reliability_type_(_reliability_type),
            client_subscribes_twice_(_client_subscribes_twice)
        {
        if (!app_->init()) {
            stop_thread_.detach();
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }

        app_->register_state_handler(
                std::bind(&initial_event_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&initial_event_test_client::on_message, this,
                        std::placeholders::_1));

        // register availability for all other services and request their event.
        for(const auto& i : service_infos_) {
            if (i.service_id == 0xFFFF && i.instance_id == 0xFFFF) {
                continue;
            }
            app_->register_availability_handler(i.service_id, i.instance_id,
                    std::bind(&initial_event_test_client::on_availability, this,
                            std::placeholders::_1, std::placeholders::_2,
                            std::placeholders::_3));
            app_->request_service(i.service_id, i.instance_id);

            std::set<vsomeip::eventgroup_t> its_eventgroups;
            its_eventgroups.insert(i.eventgroup_id);
            for (std::uint32_t j = 0; j < events_to_subscribe_; j++ ) {
                app_->request_event(i.service_id, i.instance_id,
                        static_cast<vsomeip::event_t>(i.event_id + j),
                        its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                        reliability_type_);
            }

            other_services_available_[std::make_pair(i.service_id, i.instance_id)] = false;

            if (!subscribe_on_available_) {
                if (events_to_subscribe_ == 1) {
                    app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                    vsomeip::DEFAULT_MAJOR);

                    std::lock_guard<std::mutex> its_lock(received_notifications_mutex_);
                    other_services_received_notification_[std::make_pair(i.service_id, i.event_id)] = 0;
                } else if (events_to_subscribe_ > 1) {
                    if (!subscribe_only_one_) {
                        for (std::uint32_t j = 0; j < events_to_subscribe_; j++ ) {
                            app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                            vsomeip::DEFAULT_MAJOR,
                                            static_cast<vsomeip::event_t>(i.event_id + j));
                            std::lock_guard<std::mutex> its_lock(received_notifications_mutex_);
                            other_services_received_notification_[std::make_pair(i.service_id, i.event_id + j)] = 0;
                        }
                    } else {
                        app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                        vsomeip::DEFAULT_MAJOR,
                                        static_cast<vsomeip::event_t>(i.event_id));
                        other_services_received_notification_[std::make_pair(i.service_id, i.event_id)] = 0;
                    }
                }
            } else {
                for (std::uint32_t j = 0; j < events_to_subscribe_; j++ ) {
                    other_services_received_notification_[std::make_pair(i.service_id, i.event_id + j)] = 0;
                }
            }
        }

        // Block all signals
        sigset_t mask;
        sigfillset(&mask);
        pthread_sigmask(SIG_BLOCK, &mask, NULL);
        // start thread which handles all of the signals
        signal_thread_ = std::thread(&initial_event_test_client::wait_for_signal, this);
        {
            std::unique_lock<std::mutex> its_lock(signal_mutex_);
            while(wait_for_signal_handler_registration_) {
                EXPECT_EQ(std::cv_status::no_timeout,
                        signal_condition_.wait_for(its_lock, std::chrono::seconds(10)));
            }
            wait_for_signal_handler_registration_ = true;
        }

        app_->start();
    }

    ~initial_event_test_client() {
        if (stop_thread_.joinable()) {
            stop_thread_.join();
        }
        if (signal_thread_.joinable()) {
            signal_thread_.join();
        }
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
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
                        << client_number_ << "] Service ["
                << std::setw(4) << std::setfill('0') << std::hex << _service << "." << _instance
                << "] is available.";

                }
            }

            if(std::all_of(other_services_available_.cbegin(),
                           other_services_available_.cend(),
                           [](const std::map<std::pair<vsomeip::service_t,
                                   vsomeip::instance_t>, bool>::value_type& v) {
                                return v.second;})) {
                VSOMEIP_INFO << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << client_number_ << "] all services are available.";
                if (subscribe_on_available_) {
                    for(const auto& i : service_infos_) {
                        if (i.service_id == 0xFFFF && i.instance_id == 0xFFFF) {
                            continue;
                        }
                        if (events_to_subscribe_ == 1 ) {
                            app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                    vsomeip::DEFAULT_MAJOR);
                        } else if (events_to_subscribe_ > 1) {
                            for (std::uint32_t j = 0; j < events_to_subscribe_; j++ ) {
                                app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                        vsomeip::DEFAULT_MAJOR,
                                        static_cast<vsomeip::event_t>(i.event_id + j));
                            }
                        }
                    }
                }
            }
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_message) {
        if(_message->get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION) {

            {
                std::lock_guard<std::mutex> its_lock(received_notifications_mutex_);
                other_services_received_notification_[std::make_pair(_message->get_service(),
                                                                 _message->get_method())]++;
                VSOMEIP_DEBUG << "[" << std::setw(4) << std::setfill('0') << std::hex
                << client_number_ << "] "
                << "Received a notification with Client/Session [" << std::setw(4)
                << std::setfill('0') << std::hex << _message->get_client() << "/"
                << std::setw(4) << std::setfill('0') << std::hex
                << _message->get_session() << "] from Service/Method ["
                << std::setw(4) << std::setfill('0') << std::hex
                << _message->get_service() << "/" << std::setw(4) << std::setfill('0')
                << std::hex << _message->get_method() << "] (now have: "
                << std::dec << other_services_received_notification_[std::make_pair(_message->get_service(),
                                                                        _message->get_method())] << ")";
            }

            std::shared_ptr<vsomeip::payload> its_payload(_message->get_payload());
            EXPECT_EQ(2u, its_payload->get_length());
            EXPECT_EQ((_message->get_service() & 0xFF00 ) >> 8, its_payload->get_data()[0]);
            EXPECT_EQ((_message->get_service() & 0xFF), its_payload->get_data()[1]);
            bool notify(false);
            if (client_subscribes_twice_) {
                // only relevant for testcase:
                // initial_event_test_diff_client_ids_same_ports_udp_client_subscribes_twice
                // check that a second subscribe triggers another initial event
                // expect notifications_to_send_after_double_subscribe == 2;
                if (is_first) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                    for(const auto& i : service_infos_) {
                        // subscribe again and expect initial events cached at rm::proxy to be received
                        // as configured routing manager only fires the event once after first susbcribe.
                        if (i.service_id == 0xFFFF && i.instance_id == 0xFFFF) {
                            continue;
                        }
                        if (!subscribe_on_available_) {
                            if (events_to_subscribe_ == 1) {
                                app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                                vsomeip::DEFAULT_MAJOR);
                            } else if (events_to_subscribe_ > 1) {
                                if (!subscribe_only_one_) {
                                    for (std::uint32_t j = 0; j < events_to_subscribe_; j++ ) {
                                        app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                                        vsomeip::DEFAULT_MAJOR,
                                                        static_cast<vsomeip::event_t>(i.event_id + j));
                                    }
                                } else {
                                    app_->subscribe(i.service_id, i.instance_id, i.eventgroup_id,
                                                    vsomeip::DEFAULT_MAJOR,
                                                    static_cast<vsomeip::event_t>(i.event_id));
                                }
                            }
                        }
                    }
                    is_first = false;
                } else {
                    bool received_initial_event_twice(false);
                    std::lock_guard<std::mutex> its_lock(received_notifications_mutex_);
                    received_initial_event_twice = all_notifications_received_twice();
                    if (received_initial_event_twice) {
                        notify = true;
                    }
                }
            } else {
                if (!service_offered_tcp_and_udp_) {
                    std::lock_guard<std::mutex> its_lock(received_notifications_mutex_);
                    if (all_notifications_received()) {
                        notify = true;
                    }
                } else {
                    if (all_notifications_received_tcp_and_udp()) {
                        notify = true;
                    }
                }
            }

            if (notify && !dont_exit_) {
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
                    bool result;
                    if (v.second == initial_event_test::notifications_to_send) {
                        result = true;
                    } else {
                        if (v.second >= initial_event_test::notifications_to_send) {
                            VSOMEIP_WARNING
                                    << "[" << std::setw(4) << std::setfill('0') << std::hex
                                        << client_number_ << "] "
                                    << " Received multiple initial events from service/instance: "
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.first
                                    << "."
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.second
                                    << " number of received events: " << v.second
                                    << ". This is caused by StopSubscribe/Subscribe messages and/or"
                                    << " service offered via UDP and TCP";
                            if (initial_event_strict_checking_) {
                                ADD_FAILURE() << "[" << std::setw(4) << std::setfill('0') << std::hex
                                    << client_number_ << "] "
                                    << " Received multiple initial events from service/instance: "
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.first
                                    << "."
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.second
                                    << " number of received events: " << v.second;
                            }
                            result = initial_event_strict_checking_ ? false : true;

                        } else {
                            result = false;
                        }
                    }

                    return result;
                }
        );
    }

    bool all_notifications_received_twice() {
        return std::all_of(
                other_services_received_notification_.cbegin(),
                other_services_received_notification_.cend(),
                [&](const std::map<std::pair<vsomeip::service_t,
                        vsomeip::method_t>, std::uint32_t>::value_type& v)
                {
                    bool result;
                    if (v.second == initial_event_test::notifications_to_send * 2) {
                        result = true;
                    } else {
                        if (v.second >= initial_event_test::notifications_to_send * 2) {
                            VSOMEIP_WARNING
                                    << __func__ << "[" << std::setw(4) << std::setfill('0') << std::hex
                                        << client_number_ << "] "
                                    << " Received multiple initial events from service/instance: "
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.first
                                    << "."
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.second
                                    << " number of received events: " << v.second
                                    << ". This is caused by StopSubscribe/Subscribe messages and/or"
                                    << " service offered via UDP and TCP";
                            if (initial_event_strict_checking_) {
                                ADD_FAILURE() << __func__ << "[" << std::setw(4) << std::setfill('0') << std::hex
                                    << client_number_ << "] "
                                    << " Received multiple initial events from service/instance: "
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.first
                                    << "."
                                    << std::setw(4) << std::setfill('0') << std::hex << v.first.second
                                    << " number of received events: " << v.second;
                            }
                            result = initial_event_strict_checking_ ? false : true;

                        } else {
                            result = false;
                        }
                    }
                    return result;
                }
        );
    }

    bool all_notifications_received_tcp_and_udp() {
        std::lock_guard<std::mutex> its_lock(received_notifications_mutex_);
        std::uint32_t received_twice(0);
        std::uint32_t received_normal(0);
        for(const auto &v : other_services_received_notification_) {
            if (!initial_event_strict_checking_ &&
                    v.second > initial_event_test::notifications_to_send * 2) {
                VSOMEIP_WARNING
                        << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << client_number_ << "] "
                        << " Received multiple initial events from service/instance: "
                        << std::setw(4) << std::setfill('0') << std::hex << v.first.first
                        << "."
                        << std::setw(4) << std::setfill('0') << std::hex << v.first.second
                        << ". This is caused by StopSubscribe/Subscribe messages and/or"
                        << " service offered via UDP and TCP";
                received_twice++;
            } else if (initial_event_strict_checking_ &&
                    v.second > initial_event_test::notifications_to_send * 2) {
                ADD_FAILURE() << "[" << std::setw(4) << std::setfill('0') << std::hex
                    << client_number_ << "] "
                    << " Received multiple initial events from service/instance: "
                    << std::setw(4) << std::setfill('0') << std::hex << v.first.first
                    << "."
                    << std::setw(4) << std::setfill('0') << std::hex << v.first.second
                    << " number of received events: " << v.second;
            } else if (v.second == initial_event_test::notifications_to_send * 2) {
                received_twice++;
            } else if(v.second == initial_event_test::notifications_to_send) {
                received_normal++;
            }
        }

        if(   received_twice == ((service_infos_.size() - 1) * events_to_subscribe_)/ 2
           && received_normal == ((service_infos_.size() - 1) * events_to_subscribe_)/ 2) {
            // routing manager stub receives the notification
            // - twice from external nodes
            // - and normal from all internal nodes
            VSOMEIP_ERROR << "[" << std::setw(4) << std::setfill('0') << std::hex
                        << client_number_ << "] "
                        << "Received notifications:"
                        << " Normal: " << received_normal
                        << " Twice: " << received_twice;
            return true;
        } else if (initial_event_strict_checking_ && (
                received_twice > ((service_infos_.size() - 1) * events_to_subscribe_)/ 2)) {
            ADD_FAILURE() << "[" << std::setw(4) << std::setfill('0') << std::hex
                << client_number_ << "] "
                << " Received too much initial events twice: " << received_twice;
        } else if (received_normal == (events_to_subscribe_ * (service_infos_.size() - 1))) {
            return true;
        }
        return false;
    }

    void wait_for_signal() {
        // register signal handler
        the_client = this;

        sigset_t handler_mask;
        sigemptyset(&handler_mask);
        sigaddset(&handler_mask, SIGUSR1);
        sigaddset(&handler_mask, SIGTERM);
        sigaddset(&handler_mask, SIGINT);
        sigaddset(&handler_mask, SIGABRT);
        pthread_sigmask(SIG_UNBLOCK, &handler_mask, NULL);

        struct sigaction sa_new, sa_old;
        sa_new.sa_handler = signal_handler;
        sa_new.sa_flags = 0;
        sigemptyset(&sa_new.sa_mask);
        ::sigaction(SIGUSR1, &sa_new, &sa_old);
        ::sigaction(SIGINT, &sa_new, &sa_old);
        ::sigaction(SIGTERM, &sa_new, &sa_old);
        ::sigaction(SIGABRT, &sa_new, &sa_old);

        {
            std::lock_guard<std::mutex> its_lock(signal_mutex_);
            wait_for_signal_handler_registration_ = false;
            signal_condition_.notify_one();
        }
        while (wait_for_stop_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
       }
    }

    void handle_signal(int _signum) {
        (void)_signum;
        std::lock_guard<std::mutex> its_lock(stop_mutex_);
        wait_for_stop_ = false;
        stop_condition_.notify_one();
    }

    void wait_for_stop() {
        static int its_call_number(0);
        its_call_number++;

        {
            std::unique_lock<std::mutex> its_lock(stop_mutex_);
            while (wait_for_stop_) {
                stop_condition_.wait_for(its_lock, std::chrono::milliseconds(100));
            }
            VSOMEIP_ERROR << "(" << std::dec << its_call_number << ") ["
                    << std::setw(4) << std::setfill('0') << std::hex
                    << client_number_
                    << "] Received notifications from all services, going down";
        }
        for (const auto& i : service_infos_) {
            if (i.service_id == 0xFFFF && i.instance_id == 0xFFFF) {
                continue;
            }
            app_->unsubscribe(i.service_id, i.instance_id, i.eventgroup_id);
        }
        app_->clear_all_handler();
        app_->stop();
    }

private:
    int client_number_;
    std::array<initial_event_test::service_info, 7> service_infos_;
    bool service_offered_tcp_and_udp_;
    std::shared_ptr<vsomeip::application> app_;
    std::map<std::pair<vsomeip::service_t, vsomeip::instance_t>, bool> other_services_available_;
    std::mutex received_notifications_mutex_;
    std::map<std::pair<vsomeip::service_t, vsomeip::method_t>, std::uint32_t> other_services_received_notification_;

    bool wait_until_registered_;
    std::mutex mutex_;
    std::condition_variable condition_;

    std::atomic<bool> wait_for_stop_;
    std::atomic<bool> is_first;

    bool subscribe_on_available_;
    std::uint32_t events_to_subscribe_;
    bool initial_event_strict_checking_;
    bool dont_exit_;
    bool subscribe_only_one_;

    std::mutex stop_mutex_;
    std::condition_variable stop_condition_;
    std::thread stop_thread_;
    bool wait_for_signal_handler_registration_;
    std::mutex signal_mutex_;
    std::condition_variable signal_condition_;
    std::thread signal_thread_;
    vsomeip::reliability_type_e reliability_type_;
    bool client_subscribes_twice_;
};

static int client_number;
static bool service_offered_tcp_and_udp;
static bool use_same_service_id;
static bool subscribe_on_available;
static std::uint32_t subscribe_multiple_events;
static bool initial_event_strict_checking;
static bool dont_exit;
static bool subscribe_only_one;
static bool client_subscribes_twice;

vsomeip::reliability_type_e reliability_type = vsomeip::reliability_type_e::RT_UNKNOWN;


extern "C" void signal_handler(int signum) {
    the_client->handle_signal(signum);
}

TEST(someip_initial_event_test, wait_for_initial_events_of_all_services)
{
    if(use_same_service_id) {
        initial_event_test_client its_sample(client_number,
                service_offered_tcp_and_udp,
                initial_event_test::service_infos_same_service_id,
                subscribe_on_available, subscribe_multiple_events,
                initial_event_strict_checking, dont_exit,
                subscribe_only_one,
                reliability_type,
                client_subscribes_twice);
    } else {
        initial_event_test_client its_sample(client_number, service_offered_tcp_and_udp,
                initial_event_test::service_infos, subscribe_on_available,
                subscribe_multiple_events, initial_event_strict_checking, dont_exit,
                subscribe_only_one,
                reliability_type,
                client_subscribes_twice);
    }
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    // Block all signals
    sigset_t mask;
    sigfillset(&mask);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
    ::testing::InitGoogleTest(&argc, argv);

    if(argc < 2) {
        std::cerr << "Please specify a client number, like: " << argv[0] << " 2 SUBSCRIBE_BEFORE_START SAME_SERVICE_ID" << std::endl;
        std::cerr << "Valid client numbers are from 0 to 0xFFFF" << std::endl;
        std::cerr << "After client number one/multiple of these flags can be specified:";
        std::cerr << " - SERVICE_OFFERED_TCP_AND_UDP flag. Set this if the service is offered via TCP and UDP" << std::endl;
        std::cerr << " - Time of subscription, valid values: [SUBSCRIBE_ON_AVAILABILITY, SUBSCRIBE_BEFORE_START], default SUBSCRIBE_BEFORE_START" << std::endl;
        std::cerr << " - SAME_SERVICE_ID flag. If set the test is run w/ multiple instances of the same service, default false" << std::endl;
        std::cerr << " - MULTIPLE_EVENTS flag. If set the test will subscribe to multiple events in the eventgroup, default false" << std::endl;
        std::cerr << " - STRICT_CHECKING flag. If set the test will only successfully finish if exactly the number of initial events were received (and not more). Default false" << std::endl;
        std::cerr << " - DONT_EXIT flag. If set the test will not exit if all notifications have been received. Default false" << std::endl;
        std::cerr << " - SUBSCRIBE_ONLY_ONE flag. If set the test will only subscribe to one event even if MULTIPLE_EVENTS is set. Default false" << std::endl;
        return 1;
    }

    client_number = std::stoi(std::string(argv[1]), nullptr);

    subscribe_on_available = false;
    initial_event_strict_checking = false;
    service_offered_tcp_and_udp = false;
    use_same_service_id = false;
    subscribe_multiple_events = 1;
    dont_exit = false;
    subscribe_only_one = false;
    client_subscribes_twice = false;
    if (argc > 2) {
        for (int i = 2; i < argc; i++) {
            if (std::string("SUBSCRIBE_ON_AVAILABILITY") == std::string(argv[i])) {
                subscribe_on_available = true;
            } else if (std::string("SUBSCRIBE_BEFORE_START") == std::string(argv[i])) {
                subscribe_on_available = false;
            } else if (std::string("SAME_SERVICE_ID") == std::string(argv[i])) {
                use_same_service_id = true;
                std::cout << "Using same service ID" << std::endl;
            } else if (std::string("MULTIPLE_EVENTS") == std::string(argv[i])) {
                subscribe_multiple_events = 5;
            } else if (std::string("STRICT_CHECKING") == std::string(argv[i])) {
                initial_event_strict_checking = true;
            } else if (std::string("DONT_EXIT") == std::string(argv[i])) {
                dont_exit = true;
            } else if (std::string("SUBSCRIBE_ONLY_ONE") == std::string(argv[i])) {
                subscribe_only_one = true;
            } else if (std::string("TCP")== std::string(argv[i])) {
                reliability_type = vsomeip::reliability_type_e::RT_RELIABLE;
                std::cout << "Using reliability type RT_RELIABLE" << std::endl;
            } else if (std::string("UDP")== std::string(argv[i])) {
                reliability_type = vsomeip::reliability_type_e::RT_UNRELIABLE;
                std::cout << "Using reliability type RT_UNRELIABLE" << std::endl;
            } else if (std::string("TCP_AND_UDP")== std::string(argv[i])) {
                reliability_type = vsomeip::reliability_type_e::RT_BOTH;
                std::cout << "Using reliability type RT_BOTH" << std::endl;
            } else if (std::string("CLIENT_SUBSCRIBES_TWICE")== std::string(argv[i])) {
                client_subscribes_twice = true;
                std::cout << "Testing for initial event after a second subscribe from same client CLIENT_SUBSCRIBES_TWICE" << std::endl;
            }
        }
    }

    return RUN_ALL_TESTS();
}
#endif
