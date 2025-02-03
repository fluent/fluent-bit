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
#include <future>

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "pending_subscription_test_globals.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class pending_subscription_test_service : public vsomeip_utilities::base_logger {
public:
    pending_subscription_test_service(struct pending_subscription_test::service_info _service_info, pending_subscription_test::test_mode_e _testmode) :
            vsomeip_utilities::base_logger("PSTS", "PENDING SUBSCRIPTION TEST SERVICE"),
            service_info_(_service_info),
            testmode_(_testmode),
            app_(vsomeip::runtime::get()->create_application("pending_subscription_test_service")),
            wait_until_registered_(true),
            wait_until_shutdown_method_called_(true),
            subscription_accepted_asynchronous_(false),
            subscription_accepted_synchronous_(false),
            offer_thread_(std::bind(&pending_subscription_test_service::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        app_->register_state_handler(
                std::bind(&pending_subscription_test_service::on_state, this,
                        std::placeholders::_1));

        // offer field
        std::set<vsomeip::eventgroup_t> its_eventgroups;
        its_eventgroups.insert(_service_info.eventgroup_id);
        app_->offer_event(service_info_.service_id, 0x1,
                    service_info_.event_id,
                    its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                    std::chrono::milliseconds::zero(),
                    false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

        its_eventgroups.clear();
        its_eventgroups.insert(static_cast<vsomeip::eventgroup_t>(_service_info.eventgroup_id+1u));

        app_->offer_event(service_info_.service_id, 0x1,
                static_cast<vsomeip::event_t>(service_info_.event_id+1u),
                its_eventgroups, vsomeip::event_type_e::ET_FIELD,
                std::chrono::milliseconds::zero(),
                false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, service_info_.shutdown_method_id,
                std::bind(&pending_subscription_test_service::on_shutdown_method_called, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, service_info_.notify_method_id,
                std::bind(&pending_subscription_test_service::on_notify_method_called, this,
                        std::placeholders::_1));

        app_->register_async_subscription_handler(service_info_.service_id,
                0x1, service_info_.eventgroup_id,
                std::bind(&pending_subscription_test_service::subscription_handler_async,
                          this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
                          std::placeholders::_4, std::placeholders::_5));
        app_->register_subscription_handler(service_info_.service_id,
                0x1, static_cast<vsomeip::eventgroup_t>(service_info_.eventgroup_id+1u),
                std::bind(&pending_subscription_test_service::subscription_handler,
                          this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
                          std::placeholders::_4));
        app_->start();
    }

    ~pending_subscription_test_service() {
        offer_thread_.join();
    }

    void offer() {
        app_->offer_service(service_info_.service_id, 0x1);
    }

    void stop() {
        app_->stop_offer_service(service_info_.service_id, 0x1);
        app_->clear_all_handler();
        app_->stop();
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

    void on_shutdown_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        app_->send(vsomeip::runtime::get()->create_response(_message));
        VSOMEIP_WARNING << "************************************************************";
        VSOMEIP_WARNING << "Shutdown method called -> going down!";
        VSOMEIP_WARNING << "************************************************************";
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_until_shutdown_method_called_ = false;
        condition_.notify_one();
    }

    void on_notify_method_called(const std::shared_ptr<vsomeip::message> &_message) {
        (void)_message;
        std::shared_ptr<vsomeip::payload> its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data( {0xDD});
        app_->notify(service_info_.service_id, service_info_.instance_id,
                service_info_.event_id, its_payload);
        app_->notify(service_info_.service_id, service_info_.instance_id,
                static_cast<vsomeip::event_t>(service_info_.event_id + 1u) , its_payload);
        notify_method_called_.set_value(true);
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

        if (testmode_ == pending_subscription_test::test_mode_e::REQUEST_TO_SD) {
            // this testcase won't send valid subscriptions -> ensure to exit
            subscription_accepted_asynchronous_ = true;
            subscription_accepted_synchronous_ = true;
        }

        while (!subscription_accepted_asynchronous_ || !subscription_accepted_synchronous_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        switch (testmode_) {
            case pending_subscription_test::test_mode_e::SUBSCRIBE:
                async_subscription_handler_(true);
                break;
            case pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE:
            case pending_subscription_test::test_mode_e::UNSUBSCRIBE:
            case pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_NACK:
            case pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_SAME_PORT:
            case pending_subscription_test::test_mode_e::SUBSCRIBE_RESUBSCRIBE_MIXED:
            case pending_subscription_test::test_mode_e::SUBSCRIBE_STOPSUBSCRIBE_SUBSCRIBE:
            case pending_subscription_test::test_mode_e::REQUEST_TO_SD:
            default:
                break;
        }

        std::future<bool> itsFuture = notify_method_called_.get_future();
        if (std::future_status::timeout == itsFuture.wait_for(std::chrono::seconds(30))) {
            ADD_FAILURE() << "notify method wasn't called within time!";
        } else {
            EXPECT_TRUE(itsFuture.get());
        }
        while (wait_until_shutdown_method_called_) {
            condition_.wait(its_lock);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        stop();
    }

    void subscription_handler_async(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid,
                                    bool _subscribed, const std::function<void(const bool)>& _cbk) {
        (void)_uid;
        (void)_gid;
        VSOMEIP_WARNING << __func__ << " " << std::hex << _client << " subscribed." << _subscribed;
        if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE) {
            async_subscription_handler_ = _cbk;
            static int was_called = 0;
            was_called++;
            EXPECT_EQ(1, was_called);
            EXPECT_TRUE(_subscribed);
            subscription_accepted_asynchronous_ = true;
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE) {
            static int count_subscribe = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribe++ : count_unsubscribe++;
            if (count_subscribe == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            _cbk(true);
            if (count_subscribe == 8 || count_unsubscribe == 7) {
                subscription_accepted_asynchronous_ = true;
            }
        } else if (testmode_ == pending_subscription_test::test_mode_e::UNSUBSCRIBE) {
            static int count_subscribe = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribe++ : count_unsubscribe++;
            if (count_subscribe == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            _cbk(true);
            if (count_subscribe == 2 || count_unsubscribe == 1) {
                subscription_accepted_asynchronous_ = true;
            }
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_NACK) {
            static int count_subscribe = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribe++ : count_unsubscribe++;
            if (count_subscribe == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            if (_subscribed) {
                _cbk(((count_subscribe + 1) % 2)); // nack every second subscription
            } else {
                _cbk(true);
            }
            if (count_subscribe == 8 || count_unsubscribe == 7) {
                subscription_accepted_asynchronous_ = true;
            }
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_SAME_PORT) {
            static int count_subscribe = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribe++ : count_unsubscribe++;
            if (count_subscribe == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            _cbk(true);
            if (count_subscribe == 8 || count_unsubscribe == 7) {
                subscription_accepted_asynchronous_ = true;
            }
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_RESUBSCRIBE_MIXED) {
            static int was_called = 0;
            was_called++;
            EXPECT_EQ(1, was_called);
            EXPECT_TRUE(_subscribed);
            _cbk(true);
            subscription_accepted_asynchronous_ = true;
        }  else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_STOPSUBSCRIBE_SUBSCRIBE) {
            static int was_called = 0;
            was_called++;
            EXPECT_EQ(1, was_called);
            EXPECT_TRUE(_subscribed);
            subscription_accepted_asynchronous_ = true;
            // this test doesn't subscribe to the second eventgroup which is handled by the asynchronous
            // subscription handler, set it to true here:
            subscription_accepted_synchronous_ = true;
            _cbk(true);
        }
    }

    bool subscription_handler(vsomeip::client_t _client, std::uint32_t _uid, std::uint32_t _gid, bool _subscribed) {
        (void)_subscribed;
        (void)_uid;
        (void)_gid;
        bool ret(false);
        VSOMEIP_WARNING << __func__ << " " << std::hex << _client << " subscribed. " << _subscribed;
        if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE) {
            static int was_called = 0;
            was_called++;
            EXPECT_EQ(1, was_called);
            EXPECT_TRUE(_subscribed);
            subscription_accepted_synchronous_ = true;
            ret = true;
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE) {
            static int count_subscribed = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribed++ : count_unsubscribe++;
            if (count_subscribed == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            if (count_subscribed == 8 && count_unsubscribe == 7) {
                subscription_accepted_synchronous_ = true;
            }
            ret = true;
        } else if (testmode_ == pending_subscription_test::test_mode_e::UNSUBSCRIBE) {
            static int count_subscribed = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribed++ : count_unsubscribe++;
            if (count_subscribed == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            if (count_subscribed == 2 && count_unsubscribe == 1) {
                subscription_accepted_synchronous_ = true;
            }
            ret = true;
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_NACK) {
            static int count_subscribed = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribed++ : count_unsubscribe++;
            if (count_subscribed == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            if (count_subscribed == 8 && count_unsubscribe == 7) {
                subscription_accepted_synchronous_ = true;
            }
            if (_subscribed) {
                ret = ((count_subscribed + 1) % 2); // nack every second subscription
            } else {
                ret = true;
            }
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_SAME_PORT) {
            static int count_subscribed = 0;
            static int count_unsubscribe = 0;
            _subscribed ? count_subscribed++ : count_unsubscribe++;

            if (count_subscribed == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            if (count_subscribed == 8 && count_unsubscribe == 7) {
                subscription_accepted_synchronous_ = true;
            }
            ret = true;
        } else if (testmode_ == pending_subscription_test::test_mode_e::SUBSCRIBE_RESUBSCRIBE_MIXED) {
            static int was_called = 0;
            was_called++;
            EXPECT_EQ(1, was_called);
            EXPECT_TRUE(_subscribed);
            subscription_accepted_synchronous_ = true;
            ret = true;
        }
        return ret;
    }

private:
    struct pending_subscription_test::service_info service_info_;
    pending_subscription_test::test_mode_e testmode_;
    std::shared_ptr<vsomeip::application> app_;

    bool wait_until_registered_;
    bool wait_until_shutdown_method_called_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic<bool> subscription_accepted_asynchronous_;
    std::atomic<bool> subscription_accepted_synchronous_;
    std::thread offer_thread_;
    std::function<void(const bool)> async_subscription_handler_;
    std::promise<bool> notify_method_called_;
};

pending_subscription_test::test_mode_e its_testmode(pending_subscription_test::test_mode_e::SUBSCRIBE);

TEST(someip_pending_subscription_test, block_subscription_handler)
{
    pending_subscription_test_service its_sample(pending_subscription_test::service, its_testmode);
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    if (argc < 2) {
        std::cerr << "Please pass a test mode to this binary like: "
                << argv[0] << " SUBSCRIBE" << std::endl;
        std::cerr << "Testmodes are [SUBSCRIBE, SUBSCRIBE_UNSUBSCRIBE, UNSUBSCRIBE, SUBSCRIBE_UNSUBSCRIBE_NACK, SUBSCRIBE_UNSUBSCRIBE_SAME_PORT]" << std::endl;
        exit(1);
    }

    std::string its_pased_testmode = argv[1];
    if (its_pased_testmode == std::string("SUBSCRIBE")) {
        its_testmode = pending_subscription_test::test_mode_e::SUBSCRIBE;
    } else if (its_pased_testmode == std::string("SUBSCRIBE_UNSUBSCRIBE")) {
        its_testmode = pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE;
    } else if (its_pased_testmode == std::string("UNSUBSCRIBE")) {
        its_testmode = pending_subscription_test::test_mode_e::UNSUBSCRIBE;
    } else if (its_pased_testmode == std::string("SUBSCRIBE_UNSUBSCRIBE_NACK")) {
        its_testmode = pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_NACK;
    } else if (its_pased_testmode == std::string("SUBSCRIBE_UNSUBSCRIBE_SAME_PORT")) {
        its_testmode = pending_subscription_test::test_mode_e::SUBSCRIBE_UNSUBSCRIBE_SAME_PORT;
    } else if (its_pased_testmode == std::string("SUBSCRIBE_RESUBSCRIBE_MIXED")) {
        its_testmode = pending_subscription_test::test_mode_e::SUBSCRIBE_RESUBSCRIBE_MIXED;
    } else if (its_pased_testmode == std::string("SUBSCRIBE_STOPSUBSCRIBE_SUBSCRIBE")) {
        its_testmode = pending_subscription_test::test_mode_e::SUBSCRIBE_STOPSUBSCRIBE_SUBSCRIBE;
    } else if (its_pased_testmode == std::string("REQUEST_TO_SD")) {
        its_testmode = pending_subscription_test::test_mode_e::REQUEST_TO_SD;
    }

    return RUN_ALL_TESTS();
}
#endif
