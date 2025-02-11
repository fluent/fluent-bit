// Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <atomic>

#include "../npdu_tests/npdu_test_rmd.hpp"

#include <vsomeip/internal/logger.hpp>
#include "npdu_test_globals.hpp"

#include "../npdu_tests/npdu_test_globals.hpp"

npdu_test_rmd::npdu_test_rmd() :
    app_(vsomeip::runtime::get()->create_application()),
    is_registered_(false),
    blocked_(false),
    offer_thread_(std::bind(&npdu_test_rmd::run, this))
{
    // TODO Auto-generated constructor stub
}

void npdu_test_rmd::init() {
    std::lock_guard<std::mutex> its_lock(mutex_);

    app_->init();

#ifdef RMD_CLIENT_SIDE
    app_->register_message_handler(npdu_test::RMD_SERVICE_ID_CLIENT_SIDE,
#elif defined (RMD_SERVICE_SIDE)
    app_->register_message_handler(npdu_test::RMD_SERVICE_ID_SERVICE_SIDE,
#endif
            npdu_test::RMD_INSTANCE_ID, npdu_test::RMD_SHUTDOWN_METHOD_ID,
            std::bind(&npdu_test_rmd::on_message_shutdown,
                    this, std::placeholders::_1));

    app_->register_state_handler(
            std::bind(&npdu_test_rmd::on_state, this,
                    std::placeholders::_1));
}

void npdu_test_rmd::start() {
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void npdu_test_rmd::stop() {
    VSOMEIP_INFO << "Stopping...";

    app_->unregister_message_handler(npdu_test::RMD_SERVICE_ID_CLIENT_SIDE,
            npdu_test::RMD_INSTANCE_ID, npdu_test::RMD_SHUTDOWN_METHOD_ID);
    app_->unregister_state_handler();
    offer_thread_.join();
    app_->stop();
}

void npdu_test_rmd::on_state(
        vsomeip::state_type_e _state) {
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

void npdu_test_rmd::on_message_shutdown(
        const std::shared_ptr<vsomeip::message>& _request) {
    (void)_request;
    std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request(false);
#ifdef RMD_CLIENT_SIDE
    static uint32_t counter = 0;
    counter++;
    VSOMEIP_INFO << counter << " of " << npdu_test::client_ids_clients.size()
            << " clients are finished.";

    if (counter == npdu_test::client_ids_clients.size()) {
        VSOMEIP_INFO << "All clients are finished, notify routing manager daemon on service side.";
        // notify the RMD_SERVICE_SIDE that he can shutdown as well
        std::this_thread::sleep_for(std::chrono::seconds(1));
        request->set_service(npdu_test::RMD_SERVICE_ID_SERVICE_SIDE);
        request->set_instance(npdu_test::RMD_INSTANCE_ID);
        request->set_method(npdu_test::RMD_SHUTDOWN_METHOD_ID);
        request->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        app_->send(request);
        std::this_thread::sleep_for(std::chrono::seconds(5));
        stop();
    }
#elif defined RMD_SERVICE_SIDE
    VSOMEIP_INFO << "All clients are finished shutting down services";
    // shutdown all services
    for(unsigned int i = 0; i < npdu_test::service_ids.size(); i++) {
        request->set_service(npdu_test::service_ids[i]);
        request->set_instance(npdu_test::instance_ids[i]);
        request->set_method(npdu_test::NPDU_SERVICE_SHUTDOWNMETHOD_ID);
        request->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        app_->send(request);
    }
    app_->stop_offer_service(npdu_test::RMD_SERVICE_ID_SERVICE_SIDE, npdu_test::RMD_INSTANCE_ID);

    VSOMEIP_INFO << "Wait a few seconds until all services are shutdown.";
    std::atomic<bool> finished(false);
    for (int i = 0; !finished && i < 20; i++) {
        app_->get_offered_services_async(
                vsomeip::offer_type_e::OT_REMOTE,
                [&](const std::vector<std::pair<vsomeip::service_t,
                                                vsomeip::instance_t>> &_services){
            if (_services.empty()) {
                finished = true;
            }
        });
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    stop();
#endif
}

void npdu_test_rmd::join_shutdown_thread() {
    shutdown_thread_.join();
}

void npdu_test_rmd::run() {
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
        condition_.wait(its_lock);
#ifdef RMD_CLIENT_SIDE
    app_->offer_service(npdu_test::RMD_SERVICE_ID_CLIENT_SIDE, npdu_test::RMD_INSTANCE_ID);
#elif defined (RMD_SERVICE_SIDE)
    app_->offer_service(npdu_test::RMD_SERVICE_ID_SERVICE_SIDE, npdu_test::RMD_INSTANCE_ID);
#endif
}

TEST(someip_npdu_test, offer_routing_manager_functionality)
{
    npdu_test_rmd daemon;
    daemon.init();
    daemon.start();
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


