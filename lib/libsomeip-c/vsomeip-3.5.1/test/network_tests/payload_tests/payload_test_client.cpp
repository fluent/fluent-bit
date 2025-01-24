// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iomanip>

#include "payload_test_client.hpp"

enum class payloadsize
    : std::uint8_t
    {
        UDS, TCP, UDP, USER_SPECIFIED
};

// this variables are changed via cmdline parameters
static bool use_tcp = false;
static bool call_service_sync = true;
static std::uint32_t sliding_window_size = vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_PAYLOAD_TESTS;
static payloadsize max_payload_size = payloadsize::UDS;
static bool shutdown_service_at_end = true;
static std::uint32_t user_defined_max_payload;
static std::uint32_t number_of_messages_to_send = 0;

payload_test_client::payload_test_client(
        bool _use_tcp,
        bool _call_service_sync,
        std::uint32_t _sliding_window_size) :
                app_(vsomeip::runtime::get()->create_application()),
                request_(vsomeip::runtime::get()->create_request(_use_tcp)),
                call_service_sync_(_call_service_sync),
                sliding_window_size_(_sliding_window_size),
                blocked_(false),
                is_available_(false),
                number_of_messages_to_send_(number_of_messages_to_send ? number_of_messages_to_send : vsomeip_test::NUMBER_OF_MESSAGES_TO_SEND_PAYLOAD_TESTS),
                number_of_sent_messages_(0),
                number_of_sent_messages_total_(0),
                number_of_acknowledged_messages_(0),
                current_payload_size_(1),
                all_msg_acknowledged_(false),
                sender_(std::bind(&payload_test_client::run, this))
{
}

bool payload_test_client::init()
{
    if (!app_->init()) {
        ADD_FAILURE() << "Couldn't initialize application";
        return false;
    }

    app_->register_state_handler(
            std::bind(&payload_test_client::on_state, this,
                    std::placeholders::_1));

    app_->register_message_handler(vsomeip::ANY_SERVICE,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID, vsomeip::ANY_METHOD,
            std::bind(&payload_test_client::on_message, this,
                    std::placeholders::_1));

    app_->register_availability_handler(vsomeip_test::TEST_SERVICE_SERVICE_ID,
            vsomeip_test::TEST_SERVICE_INSTANCE_ID,
            std::bind(&payload_test_client::on_availability, this,
                    std::placeholders::_1, std::placeholders::_2,
                    std::placeholders::_3));
    return true;
}

void payload_test_client::start()
{
    VSOMEIP_INFO << "Starting...";
    app_->start();
}

void payload_test_client::stop()
{
    VSOMEIP_INFO << "Stopping...";
    // shutdown the service
    if(shutdown_service_at_end)
    {
        shutdown_service();
    }
    app_->clear_all_handler();
}

void payload_test_client::shutdown_service()
{
    request_->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request_->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    request_->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID_SHUTDOWN);
    app_->send(request_);
}

void payload_test_client::join_sender_thread()
{
    sender_.join();
}

void payload_test_client::on_state(vsomeip::state_type_e _state)
{
    if(_state == vsomeip::state_type_e::ST_REGISTERED)
    {
        app_->request_service(vsomeip_test::TEST_SERVICE_SERVICE_ID,
                vsomeip_test::TEST_SERVICE_INSTANCE_ID, false);
    }
}

void payload_test_client::on_availability(vsomeip::service_t _service,
        vsomeip::instance_t _instance, bool _is_available)
{
    VSOMEIP_INFO << "Service [" << std::setw(4) << std::setfill('0') << std::hex
            << _service << "." << _instance << "] is "
            << (_is_available ? "available." : "NOT available.");

    if(vsomeip_test::TEST_SERVICE_SERVICE_ID == _service
            && vsomeip_test::TEST_SERVICE_INSTANCE_ID == _instance)
    {
        if(is_available_ && !_is_available)
        {
            is_available_ = false;
        }
        else if(_is_available && !is_available_)
        {
            is_available_ = true;
            send();
        }
    }
}

void payload_test_client::on_message(const std::shared_ptr<vsomeip::message>& _response)
{
    number_of_acknowledged_messages_++;

    ASSERT_EQ(_response->get_service(), vsomeip_test::TEST_SERVICE_SERVICE_ID);
    ASSERT_EQ(_response->get_instance(), vsomeip_test::TEST_SERVICE_INSTANCE_ID);

    if(call_service_sync_)
    {
        // We notify the sender thread every time a message was acknowledged
        {
            std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutex_);
            all_msg_acknowledged_ = true;
        }
        all_msg_acknowledged_cv_.notify_one();
    }
    else
    {
        // We notify the sender thread only if all sent messages have been acknowledged
        if(number_of_acknowledged_messages_ == number_of_messages_to_send_)
        {
            std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutex_);
            number_of_acknowledged_messages_ = 0;
            all_msg_acknowledged_ = true;
            all_msg_acknowledged_cv_.notify_one();
        }
        else if(number_of_acknowledged_messages_ % sliding_window_size_ == 0)
        {
            std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutex_);
            all_msg_acknowledged_ = true;
            all_msg_acknowledged_cv_.notify_one();
        }
    }
}

void payload_test_client::send()
{
    std::lock_guard<std::mutex> its_lock(mutex_);
    blocked_ = true;
    condition_.notify_one();
}

void payload_test_client::run()
{
    std::unique_lock<std::mutex> its_lock(mutex_);
    while (!blocked_)
    {
        condition_.wait(its_lock);
    }

    request_->set_service(vsomeip_test::TEST_SERVICE_SERVICE_ID);
    request_->set_instance(vsomeip_test::TEST_SERVICE_INSTANCE_ID);
    request_->set_method(vsomeip_test::TEST_SERVICE_METHOD_ID);

    // lock the mutex
    std::unique_lock<std::mutex> lk(all_msg_acknowledged_mutex_);

    std::uint32_t max_allowed_payload = get_max_allowed_payload();

    std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
    std::vector<vsomeip::byte_t> payload_data;
    bool reached_peak = false;
    for(;;)
    {
        payload_data.assign(current_payload_size_ , vsomeip_test::PAYLOAD_TEST_DATA);
        payload->set_data(payload_data);
        request_->set_payload(payload);

        watch_.reset();
        watch_.start();

        call_service_sync_ ? send_messages_sync(lk) : send_messages_async(lk);

        watch_.stop();
        print_throughput();

        // Increase array size for next iteration
        if(!reached_peak) {
            current_payload_size_ *= 2;
        } else {
            current_payload_size_ /= 2;
        }

        if(!reached_peak && current_payload_size_ > max_allowed_payload)
        {
            current_payload_size_ = max_allowed_payload;
            reached_peak = true;
        } else if(reached_peak && current_payload_size_ <= 1) {
            break;
        }
    }
    blocked_ = false;

    stop();
    std::thread t1([](){ std::this_thread::sleep_for(std::chrono::microseconds(1000000 * 5));});
    t1.join();
    app_->stop();
    std::thread t([](){ std::this_thread::sleep_for(std::chrono::microseconds(1000000 * 5));});
    t.join();
}


std::uint32_t payload_test_client::get_max_allowed_payload()
{
    std::uint32_t payload;
    switch (max_payload_size)
    {
        case payloadsize::UDS:
            // TODO
            payload = 1024 * 32 - 16;
            break;
        case payloadsize::TCP:
            // TODO
            payload = 4095 - 16;
            break;
        case payloadsize::UDP:
            payload = VSOMEIP_MAX_UDP_MESSAGE_SIZE - 16;
            break;
        case payloadsize::USER_SPECIFIED:
            payload = user_defined_max_payload;
            break;
        default:
            payload = VSOMEIP_MAX_LOCAL_MESSAGE_SIZE;
            break;
    }
    return payload;
}

void payload_test_client::send_messages_sync(std::unique_lock<std::mutex>& lk)
{
    for (number_of_sent_messages_ = 0;
            number_of_sent_messages_ < number_of_messages_to_send_;
            number_of_sent_messages_++, number_of_sent_messages_total_++)
    {
        app_->send(request_);
        // wait until the send messages has been acknowledged
        // as long we wait lk is released; after wait returns lk is reacquired
        all_msg_acknowledged_cv_.wait(lk, [&]
        {   return all_msg_acknowledged_;});
        // Reset condition variable (lk is locked again here)
        all_msg_acknowledged_ = false;
    }
}

void payload_test_client::send_messages_async(std::unique_lock<std::mutex>& lk)
{
    for (number_of_sent_messages_ = 0;
            number_of_sent_messages_ < number_of_messages_to_send_;
            number_of_sent_messages_++, number_of_sent_messages_total_++)
    {
        app_->send(request_);

        if((number_of_sent_messages_+1) % sliding_window_size_ == 0)
        {
            // wait until all send messages have been acknowledged
            // as long we wait lk is released; after wait returns lk is reacquired
            all_msg_acknowledged_cv_.wait(lk, [&]
            {   return all_msg_acknowledged_;});

            // Reset condition variable
            all_msg_acknowledged_ = false;
        }
    }
}

void payload_test_client::print_throughput()
{
    constexpr std::uint32_t usec_per_sec = 1000000;
    stop_watch::usec_t time_needed = watch_.get_total_elapsed_microseconds();
    stop_watch::usec_t time_per_message = time_needed / number_of_sent_messages_;
    std::double_t calls_per_sec = number_of_sent_messages_
            * (usec_per_sec / static_cast<double>(time_needed));
    std::double_t mbyte_per_sec = ((number_of_sent_messages_
            * current_payload_size_)
            / (static_cast<double>(time_needed) / usec_per_sec)) / (1024*1024);

    VSOMEIP_INFO<< "[ Payload Test ] : :"
    << "Payload size [byte]: " << std::dec << std::setw(8) << std::setfill('0') << current_payload_size_
    << " Messages sent: " << std::dec << std::setw(8) << std::setfill('0') << number_of_sent_messages_
    << " Meantime/message [usec]: " << std::dec << std::setw(8) << std::setfill('0') << time_per_message
    << " Calls/sec: " << std::dec << std::setw(8) << std::setfill('0') << calls_per_sec
    << " MiB/sec: " << std::dec << std::setw(8) << std::setfill('0') << mbyte_per_sec;
}

TEST(someip_payload_test, send_different_payloads)
{
    payload_test_client test_client_(use_tcp, call_service_sync, sliding_window_size);
    if (test_client_.init()) {
        test_client_.start();
        test_client_.join_sender_thread();
    }
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    std::string tcp_enable("--tcp");
    std::string udp_enable("--udp");
    std::string sync_enable("--sync");
    std::string async_enable("--async");
    std::string sliding_window_size_param("--sliding-window-size");
    std::string max_payload_size_param("--max-payload-size");
    std::string shutdown_service_disable_param("--dont-shutdown-service");
    std::string numbers_of_messages("--number-of-messages");
    std::string help("--help");

    int i = 1;
    while (i < argc)
    {
        if(tcp_enable == argv[i])
        {
            use_tcp = true;
        }
        else if(udp_enable == argv[i])
        {
            use_tcp = false;
        }
        else if(sync_enable == argv[i])
        {
            call_service_sync = true;
        }
        else if(async_enable == argv[i])
        {
            call_service_sync = false;
        }
        else if(sliding_window_size_param == argv[i] && i + 1 < argc)
        {
            i++;
            std::stringstream converter(argv[i]);
            converter >> sliding_window_size;
        }
        else if(max_payload_size_param == argv[i] && i + 1 < argc)
        {
            i++;
            if(std::string("UDS") == argv[i])
            {
                max_payload_size = payloadsize::UDS;
            }
            else if(std::string("TCP") == argv[i])
            {
                max_payload_size = payloadsize::TCP;
            }
            else if(std::string("UDP") == argv[i])
            {
                max_payload_size = payloadsize::UDP;
            }
            else {
                max_payload_size = payloadsize::USER_SPECIFIED;
                std::stringstream converter(argv[i]);
                converter >> user_defined_max_payload;
            }
        }
        else if (numbers_of_messages == argv[i]) {
            i++;
            std::stringstream converter(argv[i]);
            converter >> number_of_messages_to_send;
        }
        else if(shutdown_service_disable_param == argv[i])
        {
            shutdown_service_at_end = false;
        }
        else if(help == argv[i])
        {
            VSOMEIP_INFO << "Parameters:\n"
            << "--tcp: Send messages via TCP\n"
            << "--udp: Send messages via UDP (default)\n"
            << "--sync: Wait for acknowledge before sending next message (default)\n"
            << "--async: Send multiple messages w/o waiting for"
                " acknowledge of service\n"
            << "--sliding-window-size: Number of messages to send before waiting "
                "for acknowledge of service. Default: " << sliding_window_size << "\n"
            << "--max-payload-size: limit the maximum payloadsize of send requests. One of {"
                "UDS (=" << VSOMEIP_MAX_LOCAL_MESSAGE_SIZE << "byte), "
                "UDP (=" << VSOMEIP_MAX_UDP_MESSAGE_SIZE << "byte), "
                "TCP (=" << VSOMEIP_MAX_TCP_MESSAGE_SIZE << "byte)}, default: UDS\n"
            << "--dont-shutdown-service: Don't shutdown the service upon "
                "finishing of the payload test\n"
            << "--number-of-messages: Number of messages to send per payload size iteration\n"
            << "--help: print this help";
        }
        i++;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
