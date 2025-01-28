// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <iomanip>
#include <numeric>
#include <cmath> // for isfinite
#include <atomic>

#include "cpu_load_test_globals.hpp"
#include <vsomeip/internal/logger.hpp>
#include "cpu_load_measurer.hpp"

// for getpid
#include <sys/types.h>
#include <unistd.h>


enum protocol_e {
    PR_UNKNOWN,
    PR_TCP,
    PR_UDP
};

class cpu_load_test_client
{
public:
    cpu_load_test_client(protocol_e _protocol, std::uint32_t _number_of_calls,
                        std::uint32_t _payload_size, bool _call_service_sync,
                        bool _shutdown_service) :
            protocol_(_protocol),
            app_(vsomeip::runtime::get()->create_application("cpu_load_test_client")),
            request_(vsomeip::runtime::get()->create_request(protocol_ == protocol_e::PR_TCP)),
            call_service_sync_(_call_service_sync),
            shutdown_service_at_end_(_shutdown_service),
            sliding_window_size_(_number_of_calls),
            wait_for_availability_(true),
            is_available_(false),
            number_of_calls_(_number_of_calls),
            number_of_calls_current_(0),
            number_of_sent_messages_(0),
            number_of_sent_messages_total_(0),
            number_of_acknowledged_messages_(0),
            payload_size_(_payload_size),
            wait_for_all_msg_acknowledged_(true),
            initialized_(false),
            sender_(std::bind(&cpu_load_test_client::run, this)) {
        if (!app_->init()) {
            ADD_FAILURE() << "Couldn't initialize application";
            return;
        }
        initialized_ = true;
        app_->register_state_handler(
                std::bind(&cpu_load_test_client::on_state, this,
                        std::placeholders::_1));

        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&cpu_load_test_client::on_message, this,
                        std::placeholders::_1));

        app_->register_availability_handler(cpu_load_test::service_id,
                cpu_load_test::instance_id,
                std::bind(&cpu_load_test_client::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        VSOMEIP_INFO << "Starting...";
        app_->start();
    }

    ~cpu_load_test_client() {
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_for_availability_ = false;
            condition_.notify_one();
        }
        {
            std::lock_guard<std::mutex> its_lock(all_msg_acknowledged_mutex_);
            wait_for_all_msg_acknowledged_ = false;
            all_msg_acknowledged_cv_.notify_one();
        }
        sender_.join();
    }

private:
    void stop() {
        VSOMEIP_INFO << "Stopping...";
        // shutdown the service
        if(shutdown_service_at_end_)
        {
            shutdown_service();
        }
        app_->clear_all_handler();
    }

    void on_state(vsomeip::state_type_e _state) {
        if(_state == vsomeip::state_type_e::ST_REGISTERED)
        {
            app_->request_service(cpu_load_test::service_id,
                    cpu_load_test::instance_id);
        }
    }

    void on_availability(vsomeip::service_t _service,
                         vsomeip::instance_t _instance, bool _is_available) {
        VSOMEIP_INFO << "Service [" << std::setw(4) << std::setfill('0')
                << std::hex << _service << "." << _instance << "] is "
                << (_is_available ? "available." : "NOT available.");

        if (cpu_load_test::service_id == _service
                && cpu_load_test::instance_id == _instance) {
            if (is_available_ && !_is_available) {
                is_available_ = false;
            } else if (_is_available && !is_available_) {
                is_available_ = true;
                std::lock_guard<std::mutex> its_lock(mutex_);
                wait_for_availability_ = false;
                condition_.notify_one();
            }
        }
    }
    void on_message(const std::shared_ptr<vsomeip::message> &_response) {

        number_of_acknowledged_messages_++;
        ASSERT_EQ(_response->get_service(), cpu_load_test::service_id);
        ASSERT_EQ(_response->get_method(), cpu_load_test::method_id);
        if(call_service_sync_)
        {
            // We notify the sender thread every time a message was acknowledged
            std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutex_);
            wait_for_all_msg_acknowledged_ = false;
            all_msg_acknowledged_cv_.notify_one();
        }
        else
        {
            // We notify the sender thread only if all sent messages have been acknowledged
            if(number_of_acknowledged_messages_ == number_of_calls_current_)
            {
                std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutex_);
                number_of_acknowledged_messages_ = 0;
                wait_for_all_msg_acknowledged_ = false;
                all_msg_acknowledged_cv_.notify_one();
            }
            else if(number_of_acknowledged_messages_ % sliding_window_size_ == 0)
            {
                std::lock_guard<std::mutex> lk(all_msg_acknowledged_mutex_);
                wait_for_all_msg_acknowledged_ = false;
                all_msg_acknowledged_cv_.notify_one();
            }
        }
    }

    void run() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_for_availability_) {
            condition_.wait(its_lock);
        }

        request_->set_service(cpu_load_test::service_id);
        request_->set_instance(cpu_load_test::instance_id);
        request_->set_method(cpu_load_test::method_id);
        std::shared_ptr<vsomeip::payload> payload = vsomeip::runtime::get()->create_payload();
        std::vector<vsomeip::byte_t> payload_data;
        payload_data.assign(payload_size_, cpu_load_test::load_test_data);
        payload->set_data(payload_data);
        request_->set_payload(payload);

        // lock the mutex
        for(std::uint32_t i=0; i <= number_of_calls_; i++) {
            number_of_calls_current_ = i;
            sliding_window_size_ = i;
            std::unique_lock<std::mutex> lk(all_msg_acknowledged_mutex_);
            call_service_sync_ ? send_messages_sync(lk, i) : send_messages_async(lk, i);
        }
        const double average_load(std::accumulate(results_.begin(), results_.end(), 0.0) / static_cast<double>(results_.size()));
        VSOMEIP_INFO << "Sent: " << number_of_sent_messages_total_
            << " messages in total (excluding control messages). This caused: "
            << std::fixed << std::setprecision(2)
            << average_load << "% load in average (average of "
            << results_.size() << " measurements).";

        std::vector<double> results_no_zero;
        for(const auto &v : results_) {
            if(v > 0.0) {
                results_no_zero.push_back(v);
            }
        }
        const double average_load_no_zero(std::accumulate(results_no_zero.begin(), results_no_zero.end(), 0.0) / static_cast<double>(results_no_zero.size()));
        VSOMEIP_INFO << "Sent: " << number_of_sent_messages_total_
            << " messages in total (excluding control messages). This caused: "
            << std::fixed << std::setprecision(2)
            << average_load_no_zero << "% load in average, if measured "
            << "cpu load was greater zero (average of "
            << results_no_zero.size() << " measurements).";

        wait_for_availability_ = true;

        stop();
        if (initialized_) {
            app_->stop();
        }
    }


    void send_messages_sync(std::unique_lock<std::mutex>& lk, std::uint32_t _messages_to_send) {
        cpu_load_measurer c(static_cast<std::uint32_t>(::getpid()));
        send_service_start_measuring(true);
        c.start();
        for (number_of_sent_messages_ = 0;
                number_of_sent_messages_ < _messages_to_send;
                number_of_sent_messages_++, number_of_sent_messages_total_++)
        {
            app_->send(request_);
            // wait until the send messages has been acknowledged
            while(wait_for_all_msg_acknowledged_) {
                all_msg_acknowledged_cv_.wait(lk);
            }
            wait_for_all_msg_acknowledged_ = true;
        }
        c.stop();
        send_service_start_measuring(false);
        VSOMEIP_DEBUG << "Synchronously sent " << std::setw(4) << std::setfill('0')
            << number_of_sent_messages_ << " messages. CPU load [%]: "
            << std::fixed << std::setprecision(2)
            << (std::isfinite(c.get_cpu_load()) ? c.get_cpu_load() : 0.0);
        results_.push_back(std::isfinite(c.get_cpu_load()) ? c.get_cpu_load() : 0.0);

    }

    void send_messages_async(std::unique_lock<std::mutex>& lk, std::uint32_t _messages_to_send) {
        cpu_load_measurer c(static_cast<std::uint32_t>(::getpid()));
        send_service_start_measuring(true);
        c.start();
        for (number_of_sent_messages_ = 0;
                number_of_sent_messages_ < _messages_to_send;
                number_of_sent_messages_++, number_of_sent_messages_total_++)
        {
            app_->send(request_);
            if((number_of_sent_messages_+1) % sliding_window_size_ == 0)
            {
                // wait until all send messages have been acknowledged
                while(wait_for_all_msg_acknowledged_) {
                    all_msg_acknowledged_cv_.wait(lk);
                }
                wait_for_all_msg_acknowledged_ = true;
            }
        }
        c.stop();
        send_service_start_measuring(false);
        VSOMEIP_DEBUG << "Asynchronously sent " << std::setw(4) << std::setfill('0')
            << number_of_sent_messages_ << " messages. CPU load [%]: "
            << std::fixed << std::setprecision(2)
            << (std::isfinite(c.get_cpu_load()) ? c.get_cpu_load() : 0.0);
        results_.push_back(std::isfinite(c.get_cpu_load()) ? c.get_cpu_load() : 0.0);
    }

    void send_service_start_measuring(bool _start_measuring) {
        std::shared_ptr<vsomeip::message> m = vsomeip::runtime::get()->create_request(protocol_ == protocol_e::PR_TCP);
        m->set_service(cpu_load_test::service_id);
        m->set_instance(cpu_load_test::instance_id);
        _start_measuring ? m->set_method(cpu_load_test::method_id_cpu_measure_start) : m->set_method(cpu_load_test::method_id_cpu_measure_stop);
        app_->send(m);
    }

    void shutdown_service() {
        request_->set_service(cpu_load_test::service_id);
        request_->set_instance(cpu_load_test::instance_id);
        request_->set_method(cpu_load_test::method_id_shutdown);
        app_->send(request_);
    }

private:
    protocol_e protocol_;
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> request_;
    bool call_service_sync_;
    bool shutdown_service_at_end_;
    std::uint32_t sliding_window_size_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool wait_for_availability_;
    bool is_available_;
    const std::uint32_t number_of_calls_;
    std::uint32_t number_of_calls_current_;
    std::uint32_t number_of_sent_messages_;
    std::uint32_t number_of_sent_messages_total_;
    std::uint32_t number_of_acknowledged_messages_;

    std::uint32_t payload_size_;

    bool wait_for_all_msg_acknowledged_;
    std::mutex all_msg_acknowledged_mutex_;
    std::condition_variable all_msg_acknowledged_cv_;
    std::vector<double> results_;
    std::atomic<bool> initialized_;
    std::thread sender_;
};


// this variables are changed via cmdline parameters
static protocol_e protocol(protocol_e::PR_UNKNOWN);
static std::uint32_t number_of_calls(0);
static std::uint32_t payload_size(40);
static bool call_service_sync(true);
static bool shutdown_service(true);


TEST(someip_load_test, DISABLED_send_messages_and_measure_cpu_load)
{
    cpu_load_test_client test_client_(protocol, number_of_calls, payload_size, call_service_sync, shutdown_service);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    int i = 0;
    while (i < argc) {
        if(std::string("--protocol") == std::string(argv[i])
        || std::string("-p") == std::string(argv[i])) {
            if(std::string("udp") == std::string(argv[i+1]) ||
                    std::string("UDP") == std::string(argv[i+1])) {
                protocol = protocol_e::PR_UDP;
                i++;
            } else if(std::string("tcp") == std::string(argv[i+1]) ||
                    std::string("TCP") == std::string(argv[i+1])) {
                protocol = protocol_e::PR_TCP;
                i++;
            }
        } else if(std::string("--calls") == std::string(argv[i])
        || std::string("-c") == std::string(argv[i])) {
            try {
                number_of_calls = static_cast<std::uint32_t>(std::stoul(std::string(argv[i+1]), nullptr, 10));
            } catch (const std::exception &e) {
                std::cerr << "Please specify a valid value for number of calls" << std::endl;
                return(EXIT_FAILURE);
            }
            i++;
        } else if(std::string("--mode") == std::string(argv[i])
        || std::string("-m") == std::string(argv[i])) {
            if(std::string("sync") == std::string(argv[i+1]) ||
                    std::string("SYNC") == std::string(argv[i+1])) {
                call_service_sync = true;
                i++;
            } else if(std::string("async") == std::string(argv[i+1]) ||
                    std::string("ASYNC") == std::string(argv[i+1])) {
                call_service_sync = false;
                i++;
            }
        } else if(std::string("--payload-size") == std::string(argv[i])
        || std::string("-pl") == std::string(argv[i])) {
            try {
                payload_size = static_cast<std::uint32_t>(std::stoul(std::string(argv[i+1]), nullptr, 10));
            } catch (const std::exception &e) {
                std::cerr << "Please specify a valid values for payload size" << std::endl;
                return(EXIT_FAILURE);
            }
            i++;
        } else if(std::string("--help") == std::string(argv[i])
        || std::string("-h") == std::string(argv[i])) {
            std::cout << "Available options:" << std::endl;
            std::cout << "--protocol|-p: valid values TCP or UDP" << std::endl;
            std::cout << "--calls|-c: number of message calls to do" << std::endl;
            std::cout << "--mode|-m: mode sync or async" << std::endl;
            std::cout << "--payload-size|-pl: payload size in Bytes default: 40" << std::endl;
        }
        i++;
    }

    if(protocol == protocol_e::PR_UNKNOWN) {
        std::cerr << "Please specify valid protocol mode, see --help" << std::endl;
        return(EXIT_FAILURE);
    }
    if(!number_of_calls) {
        std::cerr << "Please specify valid number of calls, see --help" << std::endl;
        return(EXIT_FAILURE);
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
