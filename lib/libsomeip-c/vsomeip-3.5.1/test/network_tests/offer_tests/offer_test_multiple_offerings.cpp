#include <atomic>
#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <vsomeip/internal/logger.hpp>

#include <vsomeip/vsomeip.hpp>

using namespace vsomeip;
using namespace std::chrono_literals;

constexpr auto TIMEOUT_RESPONSE = 1000ms;
constexpr auto REQUESTS_NUMBER = 10;

class common {
public:
    virtual void on_availability(service_t _service_id, instance_t _instance_id, bool _is_available);

public:
    instance_t instance_id_;
    service_t service_id_;
    major_version_t major_version_;
    minor_version_t minor_version_;
    std::shared_ptr<application> app_;
    std::thread thread_id_;
    std::condition_variable condition_availability_;
    std::atomic_bool availability_;
    std::atomic_bool msg_sent_;
};

void common::on_availability(service_t _service_id, instance_t _instance_id, bool _is_available) {
    if (_service_id == service_id_ && _instance_id == instance_id_) {
        if (_is_available) {
            // NOTE: Using the most strict memory ordering operation.
            // Refer to https://en.cppreference.com/w/cpp/atomic/memory_order for possible options
            availability_.store(true);
            condition_availability_.notify_one();
        } else {
            availability_.store(false);
        }
    }
}

class client : common {
public:
    client(service_t _service_id,
           instance_t _instance_id,
           major_version_t _major_version,
           minor_version_t _minor_version) {
        service_id_ = _service_id;
        instance_id_ = _instance_id;
        major_version_ = _major_version;
        minor_version_ = _minor_version;

        app_ = runtime::get()->create_application("client");
        app_->init();
        app_->register_availability_handler(service_id_, instance_id_,
            std::bind(&client::on_availability, this,
                std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3));

        app_->register_message_handler(
            service_id_, instance_id_, ANY_METHOD,
            std::bind(&client::on_message, this, std::placeholders::_1));
        app_->request_service(service_id_, instance_id_, major_version_, minor_version_);

        thread_id_ = std::thread(std::bind(&client::run, this));
    }

    void run() {
        app_->start();
    }

    bool was_message_received() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_message_received_.wait(lock, [=] { return message_received_.load(); });
        return message_received_.load();
    }

    std::vector<uint8_t> getReceivedPayload() {
        std::lock_guard<std::mutex> its_lock(payload_mutex_);
        return received_payload_;
    }

    bool wait_availability() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_availability_.wait(lock, [=] { return availability_.load(); });
        return availability_.load();
    }

    void send_message(const std::vector<uint8_t>& _outgoing_payload) {
        msg_sent_.store(false);
        auto request = runtime::get()->create_request();
        request->set_service(service_id_);
        request->set_instance(instance_id_);
        request->set_method(1);

        request->set_payload(runtime::get()->create_payload(_outgoing_payload));
        app_->send(request);

        std::unique_lock<std::mutex> lock(mutex_);
        condition_message_sent_.wait(lock, [=] { return msg_sent_.load(); });
    }

    ~client() {
        app_->stop();
        thread_id_.join();
    }

private:
    void on_availability(service_t _service_id, instance_t _instance_id, bool _is_available) {
        common::on_availability(_service_id, _instance_id, _is_available);
    }

    void on_message(const std::shared_ptr<message>& _message) {
        auto its_payload = _message->get_payload();
        auto const len = its_payload->get_length();

        std::stringstream msg;
        {
            std::lock_guard<std::mutex> its_lock(payload_mutex_);
            received_payload_.clear();
            for (uint32_t i = 0; i < len; ++i) {
                received_payload_.push_back(*(its_payload->get_data() + i));
                msg << std::hex << std::setw(2) << std::setfill('0') << (int)(*(its_payload->get_data() + i)) << " ";
            }
        }

        VSOMEIP_INFO << "[TEST] Got message from "
                     << std::hex << std::setw(4) << std::setfill('0') << _message->get_service() << "."
                     << std::hex << std::setw(4) << std::setfill('0') << _message->get_instance()
                     << " length " << std::dec << len << " and payload " << msg.str();
        {
            std::lock_guard<std::mutex> its_lock(mutex_);
            msg_sent_.store(true);
            condition_message_sent_.notify_one();
        }

        std::lock_guard<std::mutex> its_lock(mutex_);
        if (_message->get_service() == service_id_ && _message->get_instance() == instance_id_) {
            message_received_.store(true);
            condition_message_received_.notify_one();
        } else {
            message_received_.store(false);
        }
    }

private:
    std::condition_variable condition_message_received_;
    std::condition_variable condition_message_sent_;
    std::mutex mutex_;

    std::atomic_bool message_received_;

    std::vector<uint8_t> received_payload_;
    std::mutex payload_mutex_;
};

class server : common {
public:
    server(service_t _service_id, instance_t _instance_id, major_version_t _major_version,
           minor_version_t _minor_version) {
        service_id_ = _service_id;
        instance_id_ = _instance_id;
        major_version_ = _major_version;
        minor_version_ = _minor_version;

        app_ = runtime::get()->create_application("service");
        app_->init();

        app_->register_availability_handler(service_id_, instance_id_,
            std::bind(&server::on_availability, this,
                std::placeholders::_1, std::placeholders::_2,
                std::placeholders::_3));
        app_->register_message_handler(
            service_id_, instance_id_, ANY_METHOD,
            std::bind(&server::on_message, this, std::placeholders::_1));
        app_->offer_service(service_id_, instance_id_, major_version_, minor_version_);
        app_->request_service(service_id_, instance_id_, major_version_, minor_version_);

        thread_id_ = std::thread(std::bind(&server::run, this));
    }

    void run() { app_->start(); }

    bool is_available() { return app_->is_available(service_id_, instance_id_); }

    bool wait_availability() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_availability_.wait(lock, [=] { return availability_.load(); });
        return availability_.load();
    }

    ~server() {
        app_->stop();
        thread_id_.join();
    }

private:
    void on_message(const std::shared_ptr<message>& _message) {
        const vsomeip::length_t len = _message->get_payload()->get_length();
        std::vector<uint8_t> out_payload;
        std::stringstream msg;
        for (uint32_t i = 0; i < len; ++i) {
            out_payload.push_back(*(_message->get_payload()->get_data() + i));
            msg << std::hex << std::setw(2) << std::setfill('0') << (int)(*(_message->get_payload()->get_data() + i)) << " ";
        }
        std::shared_ptr<vsomeip::message> response = runtime::get()->create_response(_message);
        response->set_payload(vsomeip::runtime::get()->create_payload(out_payload));

        VSOMEIP_INFO << "[TEST] Sending " << msg.str();
        app_->send(response);
    }

    void on_availability(service_t _service_id, instance_t _instance_id, bool _is_available) {
        common::on_availability(_service_id, _instance_id, _is_available);
    }

private:
    std::mutex mutex_;
};

class vsomeip_daemon {
public:
    vsomeip_daemon() {
        app_ = vsomeip::runtime::get()->create_application("daemon");
        app_->init();
        run_daemon_thread_ = std::thread(std::bind(&vsomeip_daemon::run, this));
    }

    void set_routing_state(routing_state_e state) { app_->set_routing_state(state); }

    ~vsomeip_daemon() {
        app_->stop();
        run_daemon_thread_.join();
    }
private:
    void run() { app_->start(); }
private:
    std::shared_ptr<application> app_;
    std::thread run_daemon_thread_;
};

TEST(offer_test, multiple_offerings_same_service)
{
    const service_t service_id { 0xfee2 };
    const instance_t instance_id { 0x0001 };
    const major_version_t major { 1 };
    const minor_version_t minor { 0 };

    vsomeip_daemon daemon;

    server service_1(service_id, instance_id, major, minor);
    service_1.wait_availability();
    VSOMEIP_INFO << "[TEST] Service 1 is AVAILABLE";

    server service_2(service_id, instance_id, major, minor);
    service_2.wait_availability();
    VSOMEIP_INFO << "[TEST] Service 2 is AVAILABLE";

    client client(service_id, instance_id, major, minor);
    client.wait_availability();
    VSOMEIP_INFO << "[TEST] Client is AVAILABLE";

    // Without suspending the deamon, the client immediatly closes.
    daemon.set_routing_state(routing_state_e::RS_SUSPENDED);

    for (int i = 0; i < REQUESTS_NUMBER; ++i) {
        VSOMEIP_INFO << "[TEST] Sending Loop " << i;
        // NOTE: Don't remove the sleep. VSOME/IP needs some time until it sends a PONG message to
        // services. Otherwise we can't detect service availability correctly later.
        std::this_thread::sleep_for(TIMEOUT_RESPONSE);
        std::vector<uint8_t> out_payload = { uint8_t(i) };
        client.send_message(out_payload);
        // Independant of the number of offerings, the client must never fail it's assertions.
        ASSERT_TRUE(client.was_message_received()) << "Message was not received";
        // Should be safe to read the payload without locks. No one is reading or writing to it.
        EXPECT_EQ(out_payload, client.getReceivedPayload()) << "Payload was not equal";
    }
    // Both offerings must be available after the client is done.
    // Failing this availability test means one of the instances has crashed.
    ASSERT_TRUE(service_1.is_available());
    ASSERT_TRUE(service_2.is_available());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
