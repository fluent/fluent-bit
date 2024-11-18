// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "../npdu_tests/npdu_test_client.hpp"

#include <vsomeip/internal/logger.hpp>
#include "../../implementation/configuration/include/configuration.hpp"
#include "../../implementation/configuration/include/configuration_impl.hpp"
#include "../../implementation/configuration/include/configuration_plugin.hpp"
#include "../../implementation/plugin/include/plugin_manager_impl.hpp"

enum class payloadsize
    : std::uint8_t
    {
        UDS, TCP, UDP
};

// this variables are changed via cmdline parameters
static bool use_tcp = false;
static bool call_service_sync = true;
static bool wait_for_replies = true;
static std::uint32_t sliding_window_size = vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND;
static payloadsize max_payload_size = payloadsize::UDS;
static bool shutdown_service_at_end = true;

npdu_test_client::npdu_test_client(
        bool _use_tcp,
        bool _call_service_sync,
        std::uint32_t _sliding_window_size,
        bool _wait_for_replies,
        std::array<std::array<std::chrono::milliseconds, 4>, 4> _applicative_debounce) :
                app_(vsomeip::runtime::get()->create_application()),
                request_(vsomeip::runtime::get()->create_request(_use_tcp)),
                call_service_sync_(_call_service_sync),
                wait_for_replies_(_wait_for_replies),
                sliding_window_size_(_sliding_window_size),
                blocked_({false}),
                is_available_({false}), // will set first element to false, rest to 0
                number_of_messages_to_send_(vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND),
                number_of_sent_messages_{0,0,0,0},
                number_of_acknowledged_messages_{{{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}}},
                current_payload_size_({0}),
                all_msg_acknowledged_({false, false, false, false}),
                acknowledgements_{0,0,0,0},
                applicative_debounce_(_applicative_debounce),
                finished_waiter_(&npdu_test_client::wait_for_all_senders, this)
{
    senders_[0] = std::thread(&npdu_test_client::run<0>, this);
    senders_[1] = std::thread(&npdu_test_client::run<1>, this);
    senders_[2] = std::thread(&npdu_test_client::run<2>, this);
    senders_[3] = std::thread(&npdu_test_client::run<3>, this);
}

npdu_test_client::~npdu_test_client() {
    finished_waiter_.join();
}

void npdu_test_client::init()
{
    app_->init();

    app_->register_state_handler(
            std::bind(&npdu_test_client::on_state, this,
                    std::placeholders::_1));

    register_availability_handler<0>();
    register_availability_handler<1>();
    register_availability_handler<2>();
    register_availability_handler<3>();

    register_message_handler_for_all_service_methods<0>();
    register_message_handler_for_all_service_methods<1>();
    register_message_handler_for_all_service_methods<2>();
    register_message_handler_for_all_service_methods<3>();

    request_->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request_->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    if(!wait_for_replies_)
        request_->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
}

template<int service_idx>
void npdu_test_client::register_availability_handler() {
    app_->register_availability_handler(npdu_test::service_ids[service_idx],
            npdu_test::instance_ids[service_idx],
            std::bind(
                    &npdu_test_client::on_availability<service_idx>,
                    this, std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
}

template<int service_idx>
void npdu_test_client::register_message_handler_for_all_service_methods() {
    register_message_handler<service_idx, 0>();
    register_message_handler<service_idx, 1>();
    register_message_handler<service_idx, 2>();
    register_message_handler<service_idx, 3>();
}

template<int service_idx, int method_idx>
void npdu_test_client::register_message_handler() {
    app_->register_message_handler(npdu_test::service_ids[service_idx],
            npdu_test::instance_ids[service_idx],
            npdu_test::method_ids[service_idx][method_idx],
            std::bind(
                    &npdu_test_client::on_message<service_idx, method_idx>,
                    this, std::placeholders::_1));
}

void npdu_test_client::start()
{
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void npdu_test_client::stop()
{
    VSOMEIP_INFO << "Stopping...";

    app_->unregister_state_handler();

    for (unsigned int i = 0; i< npdu_test::service_ids.size(); i++) {
        app_->unregister_availability_handler(npdu_test::service_ids[i],
                                              npdu_test::instance_ids[i]);

        for(unsigned int j = 0; j < npdu_test::method_ids[i].size(); j++) {
            app_->unregister_message_handler(npdu_test::service_ids[i],
                                             npdu_test::instance_ids[i],
                                             npdu_test::method_ids[i][j]);
        }
    }

    if(shutdown_service_at_end) {
        // notify the routing manager daemon that were finished
        request_->set_service(npdu_test::RMD_SERVICE_ID_CLIENT_SIDE);
        request_->set_instance(npdu_test::RMD_INSTANCE_ID);
        request_->set_method(npdu_test::RMD_SHUTDOWN_METHOD_ID);
        request_->set_payload(vsomeip::runtime::get()->create_payload());
        request_->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        app_->send(request_);
        // sleep otherwise the app will shutdown before the message reaches the rmd
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    app_->stop();
}

void npdu_test_client::join_sender_thread() {
    for (auto& t : senders_) {
        t.join();
    }
}

void npdu_test_client::on_state(vsomeip::state_type_e _state)
{
    if(_state == vsomeip::state_type_e::ST_REGISTERED)
    {
        for (unsigned int i = 0; i< npdu_test::service_ids.size(); i++) {
            app_->request_service(npdu_test::service_ids[i],
                                  npdu_test::instance_ids[i]);
        }
    }
}

template<int service_idx>
void npdu_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available)
{
    VSOMEIP_INFO<< "Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << std::setw(4) << std::setfill('0') << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");
    if(npdu_test::service_ids[service_idx] == _service
       && npdu_test::instance_ids[service_idx] == _instance) {
        if(is_available_[service_idx] && !_is_available)
        {
            is_available_[service_idx] = false;
        }
        else if(_is_available && !is_available_[service_idx])
        {
            is_available_[service_idx] = true;
            send<service_idx>();
        }
    }
}

template<int service_idx, int method_idx>
void npdu_test_client::on_message(const std::shared_ptr<vsomeip::message>& _response) {
    (void)_response;
    //TODO make sure the replies were sent within demanded debounce times
    VSOMEIP_DEBUG << "Received reply from:" << std::setw(4) << std::setfill('0')
            << std::hex << npdu_test::service_ids[service_idx] << ":"
            << std::setw(4) << std::setfill('0') << std::hex
            << npdu_test::instance_ids[service_idx] << ":" << std::setw(4)
            << std::setfill('0') << std::hex
            << npdu_test::method_ids[service_idx][method_idx];

    if(call_service_sync_)
    {
        // We notify the sender thread every time a message was acknowledged
        std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutexes_[service_idx][method_idx]);
        all_msg_acknowledged_[service_idx][method_idx] = true;
        all_msg_acknowledged_cvs_[service_idx][method_idx].notify_one();
    }
    else
    {

        std::lock_guard<std::mutex> its_lock(number_of_acknowledged_messages_mutexes_[service_idx][method_idx]);
        number_of_acknowledged_messages_[service_idx][method_idx]++;

        // We notify the sender thread only if all sent messages have been acknowledged
        if(number_of_acknowledged_messages_[service_idx][method_idx] == number_of_messages_to_send_)
        {
            std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutexes_[service_idx][method_idx]);
            // reset
            number_of_acknowledged_messages_[service_idx][method_idx] = 0;
            all_msg_acknowledged_[service_idx][method_idx] = true;
            all_msg_acknowledged_cvs_[service_idx][method_idx].notify_one();
        } else if(number_of_acknowledged_messages_[service_idx][method_idx] % sliding_window_size == 0)
        {
            std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutexes_[service_idx][method_idx]);
            all_msg_acknowledged_[service_idx][method_idx] = true;
            all_msg_acknowledged_cvs_[service_idx][method_idx].notify_one();
        }
    }
}

template<int service_idx>
void npdu_test_client::send()
{
    std::lock_guard<std::mutex> its_lock(mutexes_[service_idx]);
    blocked_[service_idx] = true;
    conditions_[service_idx].notify_one();
}

template<int service_idx>
void npdu_test_client::run()
{
    std::unique_lock<std::mutex> its_lock(mutexes_[service_idx]);
    while (!blocked_[service_idx])
    {
        conditions_[service_idx].wait(its_lock);
    }
    current_payload_size_[service_idx] = 1;

    std::uint32_t max_allowed_payload = get_max_allowed_payload();

    for (int var = 0; var < 4; ++var) {
        payloads_[service_idx][var] = vsomeip::runtime::get()->create_payload();
        payload_data_[service_idx][var] = std::vector<vsomeip::byte_t>();
    }

    bool lastrun = false;
    while (current_payload_size_[service_idx] <= max_allowed_payload)
    {
        // prepare the payloads w/ current payloadsize
        for (int var = 0; var < 4; ++var) {
            // assign 0x11 to first, 0x22 to second...
            payload_data_[service_idx][var].assign(
                    current_payload_size_[service_idx], static_cast<vsomeip::byte_t>(0x11 * (var + 1)));
            payloads_[service_idx][var]->set_data(payload_data_[service_idx][var]);
        }

        // send the payloads to the service's methods
        if(wait_for_replies_) {
            call_service_sync_ ? send_messages_sync<service_idx>() : send_messages_async<service_idx>();
        } else {
            send_messages_and_dont_wait_for_reply<service_idx>();
        }

        // Increase array size for next iteration
        current_payload_size_[service_idx] *= 2;

        //special case to test the biggest payload possible as last test
        // 16 Bytes are reserved for the SOME/IP header
        if(current_payload_size_[service_idx] > max_allowed_payload - 16 && !lastrun)
        {
            current_payload_size_[service_idx] = max_allowed_payload - 16;
            lastrun = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    blocked_[service_idx] = false;

    {
        std::lock_guard<std::mutex> its_lock(finished_mutex_);
        finished_[service_idx] = true;
    }
}


std::uint32_t npdu_test_client::get_max_allowed_payload()
{
    std::uint32_t payload;
    switch (max_payload_size)
    {
        case payloadsize::UDS:
            payload = VSOMEIP_MAX_LOCAL_MESSAGE_SIZE;
            break;
        case payloadsize::TCP:
            payload = 4095;
            break;
        case payloadsize::UDP:
            payload = VSOMEIP_MAX_UDP_MESSAGE_SIZE;
            break;
        default:
            payload = VSOMEIP_MAX_LOCAL_MESSAGE_SIZE;
            break;
    }
    return payload;
}

template<int service_idx>
void npdu_test_client::send_messages_sync()
{
    std::thread t0 = start_send_thread_sync<service_idx, 0>();
    std::thread t1 = start_send_thread_sync<service_idx, 1>();
    std::thread t2 = start_send_thread_sync<service_idx, 2>();
    std::thread t3 = start_send_thread_sync<service_idx, 3>();
    t0.join();
    t1.join();
    t2.join();
    t3.join();
}

template<int service_idx, int method_idx>
std::thread npdu_test_client::start_send_thread_sync() {
    return std::thread([&]() {
        all_msg_acknowledged_unique_locks_[service_idx][method_idx] =
                std::unique_lock<std::mutex>
                    (all_msg_acknowledged_mutexes_[service_idx][method_idx]);

        std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request(use_tcp);
        request->set_service(npdu_test::service_ids[service_idx]);
        request->set_instance(npdu_test::instance_ids[service_idx]);
        request->set_method(npdu_test::method_ids[service_idx][method_idx]);
        request->set_payload(payloads_[service_idx][method_idx]);
        for (std::uint32_t i = 0; i < number_of_messages_to_send_; i++)
        {
            all_msg_acknowledged_[service_idx][method_idx] = false;
            app_->send(request);

            std::chrono::high_resolution_clock::time_point sent =
                    std::chrono::high_resolution_clock::now();

            while(!all_msg_acknowledged_[service_idx][method_idx]) {
                all_msg_acknowledged_cvs_[service_idx][method_idx].wait(
                        all_msg_acknowledged_unique_locks_[service_idx][method_idx]);
            }

            std::chrono::nanoseconds waited_for_response =
                    std::chrono::high_resolution_clock::now() - sent;
            if(waited_for_response < applicative_debounce_[service_idx][method_idx]) {
                // make sure we don't send faster than debounce time + max retention time
                std::this_thread::sleep_for(
                                        applicative_debounce_[service_idx][method_idx]
                                                           - waited_for_response);
            }
        }
        all_msg_acknowledged_unique_locks_[service_idx][method_idx].unlock();
    });
}

template<int service_idx>
void npdu_test_client::send_messages_async()
{
    std::thread t0 = start_send_thread_async<service_idx, 0>();
    std::thread t1 = start_send_thread_async<service_idx, 1>();
    std::thread t2 = start_send_thread_async<service_idx, 2>();
    std::thread t3 = start_send_thread_async<service_idx, 3>();
    t0.join();
    t1.join();
    t2.join();
    t3.join();
}

template<int service_idx, int method_idx>
std::thread npdu_test_client::start_send_thread_async() {
    return std::thread([&]() {
        all_msg_acknowledged_unique_locks_[service_idx][method_idx] =
                std::unique_lock<std::mutex>
                    (all_msg_acknowledged_mutexes_[service_idx][method_idx]);
        std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request(use_tcp);
        request->set_service(npdu_test::service_ids[service_idx]);
        request->set_instance(npdu_test::instance_ids[service_idx]);
        request->set_method(npdu_test::method_ids[service_idx][method_idx]);
        request->set_payload(payloads_[service_idx][method_idx]);
        for (std::uint32_t i = 0; i < number_of_messages_to_send_; i++)
        {
            app_->send(request);

            if((i+1) == number_of_messages_to_send_ || (i+1) % sliding_window_size == 0) {
                // wait until all send messages have been acknowledged
                // as long we wait lk is released; after wait returns lk is reacquired
                while(!all_msg_acknowledged_[service_idx][method_idx]) {
                    all_msg_acknowledged_cvs_[service_idx][method_idx].wait(
                            all_msg_acknowledged_unique_locks_[service_idx][method_idx]);
                }
                // Reset condition variable
                all_msg_acknowledged_[service_idx][method_idx] = false;
            }
            // make sure we don't send faster than debounce time + max retention time
            std::this_thread::sleep_for(applicative_debounce_[service_idx][method_idx]);
        }
        all_msg_acknowledged_unique_locks_[service_idx][method_idx].unlock();
    });
}

template<int service_idx>
void npdu_test_client::send_messages_and_dont_wait_for_reply()
{
    std::thread t0 = start_send_thread<service_idx, 0>();
    std::thread t1 = start_send_thread<service_idx, 1>();
    std::thread t2 = start_send_thread<service_idx, 2>();
    std::thread t3 = start_send_thread<service_idx, 3>();
    t0.join();
    t1.join();
    t2.join();
    t3.join();
}

template<int service_idx, int method_idx>
std::thread npdu_test_client::start_send_thread() {
    return std::thread([&]() {
        std::shared_ptr<vsomeip::message> request = vsomeip::runtime::get()->create_request(use_tcp);
        request->set_service(npdu_test::service_ids[service_idx]);
        request->set_instance(npdu_test::instance_ids[service_idx]);
        request->set_message_type(vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
        request->set_method(npdu_test::method_ids[service_idx][method_idx]);
        request->set_payload(payloads_[service_idx][method_idx]);
        for (std::uint32_t i = 0; i < number_of_messages_to_send_; i++)
        {
            app_->send(request);
            // make sure we don't send faster than debounce time + max retention time
            std::this_thread::sleep_for(applicative_debounce_[service_idx][method_idx]);
        }
    });
}

void npdu_test_client::wait_for_all_senders() {
    bool all_finished(false);
    while (!all_finished) {
        {
            std::lock_guard<std::mutex> its_lock(finished_mutex_);
            if (std::all_of(finished_.begin(), finished_.end(), [](bool i) { return i; })) {
                all_finished = true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    join_sender_thread();

    if (!wait_for_replies_ || !call_service_sync_) {
        // sleep longer here as sending is asynchronously and it's necessary
        // to wait until all messages have left the application
        VSOMEIP_INFO << "Sleeping for 180sec since the client is running "
                "in --dont-wait-for-replies or --async mode. "
                "Otherwise it might be possible that not all messages leave the "
                "application.";
        for(int i = 0; i < 180; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::cout << ".";
            std::cout.flush();
        }
    } else {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    stop();
}

TEST(someip_npdu_test, send_different_payloads)
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
    std::array<std::array<std::chrono::milliseconds, 4>, 4> applicative_debounce;

    // query the debouncetimes from the configuration. We want to know the
    // debounce times which the _clients_ of this service have to comply with
    // when they send requests to this service.
    // This is necessary as we must ensure a applicative debouncing greater than
    // debounce time + maximum retention time. Therefore the send threads sleep
    // for this amount of time after sending a message.
    for(int service_id = 0; service_id < 4; service_id++) {
        for(int method_id = 0; method_id < 4; method_id++) {
            std::chrono::nanoseconds debounce(0), retention(0);
            its_configuration->get_configured_timing_requests(
                    npdu_test::service_ids[service_id],
                    its_configuration->get_unicast_address(npdu_test::service_ids[service_id],
                                                           npdu_test::instance_ids[service_id]),
                    its_configuration->get_unreliable_port(
                            npdu_test::service_ids[service_id],
                            npdu_test::instance_ids[service_id]),
                    npdu_test::method_ids[service_id][method_id],
                    &debounce, &retention);
            if (debounce == std::chrono::nanoseconds(VSOMEIP_DEFAULT_NPDU_DEBOUNCING_NANO) &&
                retention == std::chrono::nanoseconds(VSOMEIP_DEFAULT_NPDU_MAXIMUM_RETENTION_NANO)) {
                // no timings specified don't don't sleep after sending...
                applicative_debounce[service_id][method_id] =
                        std::chrono::milliseconds(0);
            } else {
                // we add 1 milliseconds to sleep a little bit longer
                applicative_debounce[service_id][method_id] = std::chrono::duration_cast<
                        std::chrono::milliseconds>(debounce + retention)
                        + std::chrono::milliseconds(1);

            }

        }
    }

    npdu_test_client test_client_(use_tcp, call_service_sync,
            sliding_window_size, wait_for_replies,
            applicative_debounce);
    test_client_.init();
    test_client_.start();
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    std::string tcp_enable("--TCP");
    std::string udp_enable("--UDP");
    std::string sync_enable("--sync");
    std::string async_enable("--async");
    std::string no_reply_enable("--dont-wait-for-replies");
    std::string sliding_window_size_param("--sliding-window-size");
    std::string max_payload_size_param("--max-payload-size");
    std::string shutdown_service_disable_param("--dont-shutdown-service");
    std::string help("--help");

    int i = 1;
    while (i < argc)
    {
        if (tcp_enable == argv[i]) {
            use_tcp = true;
        } else if (udp_enable == argv[i]) {
            use_tcp = false;
        } else if (sync_enable == argv[i]) {
            call_service_sync = true;
        } else if (async_enable == argv[i]) {
            call_service_sync = false;
        } else if (no_reply_enable == argv[i]) {
            wait_for_replies = false;
        } else if (sliding_window_size_param == argv[i] && i + 1 < argc) {
            i++;
            std::stringstream converter(argv[i]);
            converter >> sliding_window_size;
        } else if (max_payload_size_param == argv[i] && i + 1 < argc) {
            i++;
            if (std::string("UDS") == argv[i]) {
                max_payload_size = payloadsize::UDS;
            } else if (std::string("TCP") == argv[i]) {
                max_payload_size = payloadsize::TCP;
            } else if (std::string("UDP") == argv[i]) {
                max_payload_size = payloadsize::UDP;
            }
        } else if (shutdown_service_disable_param == argv[i]) {
            shutdown_service_at_end = false;
        } else if (help == argv[i]) {
            VSOMEIP_INFO << "Parameters:\n"
            << "--TCP: Send messages via TCP\n"
            << "--UDP: Send messages via UDP (default)\n"
            << "--sync: Wait for acknowledge before sending next message (default)\n"
            << "--async: Send multiple messages w/o waiting for"
                " acknowledge of service\n"
            << "--dont-wait-for-replies: Just send out the messages w/o waiting for "
                "a reply by the service (use REQUEST_NO_RETURN message type)\n"
            << "--sliding-window-size: Number of messages to send before waiting "
                "for acknowledge of service. Default: " << sliding_window_size << "\n"
            << "--max-payload-size: limit the maximum payloadsize of send requests. One of {"
                "UDS (=" << VSOMEIP_MAX_LOCAL_MESSAGE_SIZE << "byte), "
                "UDP (=" << VSOMEIP_MAX_UDP_MESSAGE_SIZE << "byte), "
                "TCP (=" << VSOMEIP_MAX_TCP_MESSAGE_SIZE << "byte)}, default: UDS\n"
            << "--dont-shutdown-service: Don't shutdown the service upon "
                "finishing of the payload test\n"
            << "--help: print this help";
        }
        i++;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
