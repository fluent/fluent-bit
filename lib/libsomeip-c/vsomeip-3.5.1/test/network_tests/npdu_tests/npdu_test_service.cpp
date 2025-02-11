// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "../npdu_tests/npdu_test_service.hpp"
#include "../npdu_tests/npdu_test_globals.hpp"

#include <vsomeip/internal/logger.hpp>
#include "../../implementation/configuration/include/configuration.hpp"
#include "../../implementation/configuration/include/configuration_impl.hpp"
#include "../../implementation/configuration/include/configuration_plugin.hpp"
#include "../../implementation/plugin/include/plugin_manager_impl.hpp"



// this variable is set during compile time to create 4 service binaries of
// which each of them offers a service.
// Based on this number the service id, instance id and method ids are
// selected from the arrays defined in npdu_test_globals.hpp
#ifndef SERVICE_NUMBER
#define SERVICE_NUMBER 0
#endif

npdu_test_service::npdu_test_service(vsomeip::service_t _service_id,
                                                 vsomeip::instance_t _instance_id,
                                                 std::array<vsomeip::method_t, 4> _method_ids,
                                                 std::array<std::chrono::nanoseconds, 4> _debounce_times,
                                                 std::array<std::chrono::nanoseconds, 4> _max_retention_times) :
                app_(vsomeip::runtime::get()->create_application()),
                is_registered_(false),
                method_ids_(_method_ids),
                debounce_times_(_debounce_times),
                max_retention_times_(_max_retention_times),
                service_id_(_service_id),
                instance_id_(_instance_id),
                blocked_(false),
                allowed_to_shutdown_(false),
                number_of_received_messages_(0),
                offer_thread_(std::bind(&npdu_test_service::run, this)),
                shutdown_thread_(std::bind(&npdu_test_service::stop, this))
{
    // init timepoints of last received message to one hour before now.
    // needed that the first message which arrives isn't registered as undershot
    // debounce time
    for(auto &tp : timepoint_last_received_message_) {
        tp = std::chrono::steady_clock::now() - std::chrono::hours(1);
    }
}

void npdu_test_service::init()
{
    std::lock_guard<std::mutex> its_lock(mutex_);

    app_->init();

    register_message_handler<0>();
    register_message_handler<1>();
    register_message_handler<2>();
    register_message_handler<3>();

    app_->register_message_handler(service_id_, instance_id_,
            npdu_test::NPDU_SERVICE_SHUTDOWNMETHOD_ID,
            std::bind(&npdu_test_service::on_message_shutdown, this,
                    std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&npdu_test_service::on_state, this,
                    std::placeholders::_1));
}

template <int method_idx>
void npdu_test_service::register_message_handler() {
    app_->register_message_handler(service_id_, instance_id_, method_ids_[method_idx],
            std::bind(&npdu_test_service::on_message<method_idx>, this,
                    std::placeholders::_1));
}

void npdu_test_service::start()
{
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void npdu_test_service::stop()
{
    std::unique_lock<std::mutex> its_lock(shutdown_mutex_);
    while (!allowed_to_shutdown_) {
        shutdown_condition_.wait(its_lock);
    }

    VSOMEIP_INFO << "Stopping...";
    if (!undershot_debounce_times_.empty()) {
        std::chrono::microseconds sum(0);
        for (const auto t : undershot_debounce_times_) {
            sum += t;
        }
        double average = static_cast<double>(sum.count())/static_cast<double>(undershot_debounce_times_.size());
        VSOMEIP_INFO << "["
                << std::setw(4) << std::setfill('0') << std::hex << service_id_ << "."
                << std::setw(4) << std::setfill('0') << std::hex << instance_id_ << "]: "
                << " Debounce time was undershot " << std::dec << undershot_debounce_times_.size() << "/" << number_of_received_messages_
                << "(" << std::setprecision(2) << (static_cast<double>(undershot_debounce_times_.size()) / static_cast<double>(number_of_received_messages_)) * 100.00
                << "%) on average: " << std::setprecision(4) << average << "µs";
    }
    app_->unregister_message_handler(service_id_, instance_id_, method_ids_[0]);
    app_->unregister_message_handler(service_id_, instance_id_, method_ids_[1]);
    app_->unregister_message_handler(service_id_, instance_id_, method_ids_[2]);
    app_->unregister_message_handler(service_id_, instance_id_, method_ids_[3]);
    app_->unregister_message_handler(service_id_,
            instance_id_, npdu_test::NPDU_SERVICE_SHUTDOWNMETHOD_ID);
    app_->unregister_state_handler();
    offer_thread_.join();
    stop_offer();
    app_->stop();
}

void npdu_test_service::offer()
{
    app_->offer_service(service_id_, instance_id_);
}

void npdu_test_service::stop_offer()
{
    app_->stop_offer_service(service_id_, instance_id_);
}

void npdu_test_service::join_shutdown_thread() {
    shutdown_thread_.join();
}

void npdu_test_service::on_state(vsomeip::state_type_e _state)
{
    VSOMEIP_INFO << "Application " << app_->get_name() << " is "
            << (_state == vsomeip::state_type_e::ST_REGISTERED ? "registered." :
                    "deregistered.");

    if(_state == vsomeip::state_type_e::ST_REGISTERED)
    {
        if(!is_registered_)
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            is_registered_ = true;
            blocked_ = true;
            // "start" the run method thread
            condition_.notify_one();
        }
    }
    else
    {
        is_registered_ = false;
    }
}

template<int method_idx>
void npdu_test_service::check_times() {
    std::lock_guard<std::mutex> its_lock(timepoint_mutexes_[method_idx]);
    // what time is it?
    std::chrono::steady_clock::time_point now =
            std::chrono::steady_clock::now();
    // how long is it since we received the last message?
    std::chrono::nanoseconds time_since_last_message =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now - timepoint_last_received_message_[method_idx]);
    // store the current time
    timepoint_last_received_message_[method_idx] = now;

    // check if the debounce time was undershot
    if (time_since_last_message < debounce_times_[method_idx]) {
        const auto time_undershot = std::chrono::duration_cast<
                std::chrono::microseconds>(debounce_times_[method_idx] - time_since_last_message);
        undershot_debounce_times_.push_back(time_undershot);
    }
    // check if maximum retention time was exceeded
    // Disabled as it can't be guaranteed that exact every max retention time a
    // message leaves the client endpoint.
#if 0
    if(time_since_last_message > max_retention_times_[method_idx]) {
        VSOMEIP_ERROR << std::setw(4) << std::setfill('0') << std::hex
                << service_id_ << ":" << std::setw(4) << std::setfill('0')
                << std::hex << instance_id_ << ":" << std::setw(4) << std::setfill('0')
                << std::hex << npdu_test::method_ids[SERVICE_NUMBER][method_idx]
                << ": max_retention_time exceeded by: " << std::dec
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                        time_since_last_message - max_retention_times_[method_idx]).count()
                << "ms";
        GTEST_FATAL_FAILURE_("Max retention time was exceeded");
    }
#endif
}

template<int method_idx>
void npdu_test_service::on_message(const std::shared_ptr<vsomeip::message>& _request)
{
    number_of_received_messages_++;
    check_times<method_idx>();
    VSOMEIP_DEBUG << __func__ << " 0x" << std::setw(4) << std::setfill('0') << std::hex
            << method_ids_[method_idx] << " payload size: "
            << std::dec << _request->get_payload()->get_length();
    if(_request->get_message_type() != vsomeip::message_type_e::MT_REQUEST_NO_RETURN) {
        std::shared_ptr<vsomeip::message> its_response =
                vsomeip::runtime::get()->create_response(_request);
        app_->send(its_response);
    }
}

void npdu_test_service::on_message_shutdown(
        const std::shared_ptr<vsomeip::message>& _request)
{
    (void)_request;
    VSOMEIP_DEBUG << "Number of received messages: " << number_of_received_messages_;
    VSOMEIP_INFO << "Shutdown method was called, going down now.";

    std::lock_guard<std::mutex> its_lock(shutdown_mutex_);
    allowed_to_shutdown_ = true;
    shutdown_condition_.notify_one();
}

void npdu_test_service::run()
{
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);

    offer();
}

TEST(someip_npdu_test, offer_service_and_check_debounce_times)
{
    // get the configuration
    std::shared_ptr<vsomeip::configuration> its_configuration;
    auto its_plugin = vsomeip::plugin_manager::get()->get_plugin(
            vsomeip::plugin_type_e::CONFIGURATION_PLUGIN, VSOMEIP_CFG_LIBRARY);
    if (its_plugin) {
        auto its_config_plugin = std::dynamic_pointer_cast<vsomeip::configuration_plugin>(its_plugin);
        if (its_config_plugin) {
            its_configuration = its_config_plugin->get_configuration("","");
        }
    }
    if (!its_configuration) {
        ADD_FAILURE() << "No configuration object. "
                "Either memory overflow or loading error detected!";
        return;
    }

    // used to store the debounce times
    std::array<std::chrono::nanoseconds, 4> debounce_times;
    std::array<std::chrono::nanoseconds, 4> max_retention_times;


    // query the debouncetimes from the configuration. We want to know the
    // debounce times which the _clients_ of this service have to comply with
    // when they send requests to this service. This is necessary as we want to
    // check on the service side if they adhere to them.
    // client one will only query method one, client two will only query method
    // two and so on.
    for(int i = 0; i < 4; i++) {
        std::chrono::nanoseconds debounce(0), retention(0);
        its_configuration->get_configured_timing_requests(
                        npdu_test::service_ids[SERVICE_NUMBER],
                        its_configuration->get_unicast_address().to_string(),
                        its_configuration->get_unreliable_port(
                                npdu_test::service_ids[SERVICE_NUMBER],
                                npdu_test::instance_ids[SERVICE_NUMBER]),
                        npdu_test::method_ids[SERVICE_NUMBER][i],
                        &debounce_times[i],
                        &max_retention_times[i]);
        if (debounce == std::chrono::nanoseconds(VSOMEIP_DEFAULT_NPDU_DEBOUNCING_NANO) &&
            retention == std::chrono::nanoseconds(VSOMEIP_DEFAULT_NPDU_MAXIMUM_RETENTION_NANO)) {
            // no timings specified - checks in check_times() should never
            // report an error in this case.
            // set debounce time to 0 this can't be undershot
            debounce_times[i] = std::chrono::nanoseconds(0);
            // set max retention time its max, this won't be exceeded
            max_retention_times[i] = std::chrono::nanoseconds::max();
        }
    }

    npdu_test_service test_service(
            npdu_test::service_ids[SERVICE_NUMBER],
            npdu_test::instance_ids[SERVICE_NUMBER],
            npdu_test::method_ids[SERVICE_NUMBER],
            debounce_times, max_retention_times);
    test_service.init();
    test_service.start();
    test_service.join_shutdown_thread();
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    int i = 1;
    while (i < argc)
    {
        if(std::string("--help") == argv[i])
        {
            VSOMEIP_INFO << "Parameters:\n"
                    << "--help: print this help";
        }
        i++;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
