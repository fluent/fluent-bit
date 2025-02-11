// Copyright (C) 2016-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#include "../implementation/service_discovery/include/constants.hpp"
#include "../implementation/utility/include/bithelper.hpp"

#include <cstdint>
#include <thread>
#include <cstring>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace vsomeip_ctrl {

class vsomeip_sender {
public:
    vsomeip_sender(bool _use_tcp,
                   const std::vector<vsomeip::byte_t>& _user_message,
                   vsomeip::instance_t _instance) :
        use_tcp_(_use_tcp),
        user_message_(_user_message),
        instance_(_instance),
        app_(vsomeip::runtime::get()->create_application("vsomeip_ctrl")),
        wait_service_available_(true),
        service_id_(0x0),
        method_id_(0x0),
        length_(0),
        client_id_(0x0),
        interface_version_(0x0),
        message_type_(vsomeip::message_type_e::MT_UNKNOWN),
        return_code_(vsomeip::return_code_e::E_UNKNOWN),
        wait_for_answer_(true)
    {
        send_thread_ = std::thread{&vsomeip_sender::send, this};

        if (user_message_.size() < VSOMEIP_PAYLOAD_POS) {
            VSOMEIP_ERROR << "Provided message is to short, min. length "
                    "is 16 Bytes, exiting.";
            exit(EXIT_FAILURE);
        }

        service_id_ = vsomeip::bithelper::read_uint16_be(&user_message_[VSOMEIP_SERVICE_POS_MIN]);
        method_id_  = vsomeip::bithelper::read_uint16_be(&user_message_[VSOMEIP_METHOD_POS_MIN]);
        length_     = vsomeip::bithelper::read_uint32_be(&user_message_[VSOMEIP_LENGTH_POS_MIN]);
        client_id_  = vsomeip::bithelper::read_uint16_be(&user_message_[VSOMEIP_CLIENT_POS_MIN]);

        interface_version_ = user_message_[VSOMEIP_INTERFACE_VERSION_POS];
        message_type_ = static_cast<vsomeip::message_type_e>(user_message_[VSOMEIP_MESSAGE_TYPE_POS]);
        return_code_ = static_cast<vsomeip::return_code_e>(user_message_[VSOMEIP_RETURN_CODE_POS]);

        validate_message();

        if (!app_->init()) {
            VSOMEIP_ERROR << "Couldn't initialize application";
            exit(EXIT_FAILURE);
        }
        app_->register_state_handler(
                std::bind(&vsomeip_sender::on_state, this,
                        std::placeholders::_1));
        app_->register_message_handler(vsomeip::ANY_SERVICE,
                vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
                std::bind(&vsomeip_sender::on_message, this,
                        std::placeholders::_1));
        app_->register_availability_handler(service_id_, instance_,
                std::bind(&vsomeip_sender::on_availability, this,
                        std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        app_->start();
    };

    void stop(int _exit_code) {
        app_->clear_all_handler();
        app_->release_service(service_id_, instance_);
        app_->stop();
        exit(_exit_code);
    }

    ~vsomeip_sender() {
        send_thread_.join();
    }

    void on_state(vsomeip::state_type_e _state) {
        VSOMEIP_INFO << "Application " << app_->get_name() << " is "
        << (_state == vsomeip::state_type_e::ST_REGISTERED ?
                "registered." : "deregistered.");

        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            app_->request_service(service_id_, instance_);
        }
    }

    void on_availability(vsomeip::service_t _service,
            vsomeip::instance_t _instance, bool _is_available) {
        if(_is_available) {
            VSOMEIP_INFO << "Service [" << std::setw(4) << std::setfill('0')
            << std::hex << _service << "." << _instance << "] is available.";
            std::lock_guard<std::mutex> its_lock(mutex_);
            wait_service_available_ = false;
            condition_.notify_one();
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message> &_response) {
        VSOMEIP_INFO << "Received a response from Service ["
            << std::setfill('0') << std::hex
            << std::setw(4) << _response->get_service() << "."
            << std::setw(4) << _response->get_instance() << "]:";
        VSOMEIP_INFO << "########## begin message";
        VSOMEIP_INFO << std::hex << std::setw(4)  << std::setfill('0')
                << _response->get_service()
                << std::hex << std::setw(4) << std::setfill('0')
                << _response->get_method()
                << " # service id / instance id";
        VSOMEIP_INFO << std::hex << std::setw(8)  << std::setfill('0')
                << _response->get_length() << " # length";
        VSOMEIP_INFO << std::hex << std::setw(4)  << std::setfill('0')
                << _response->get_client()
                << std::hex << std::setw(4) << std::setfill('0')
                << _response->get_session()
                << " # client id / session id";
        VSOMEIP_INFO  << std::hex << std::setw(2)  << std::setfill('0')
                << static_cast<std::uint16_t>(_response->get_protocol_version())
                << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<std::uint16_t>(_response->get_interface_version())
                << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<std::uint16_t>(_response->get_message_type())
                << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<std::uint16_t>(_response->get_return_code())
                << " # protocol version / interface version / "
                << "message type / return code";


        std::stringstream stream;
        std::string str;
        for(unsigned int i = 0; i < _response->get_payload()->get_length(); i++) {
            stream << std::hex << std::setw(2)  << std::setfill('0')
                << static_cast<std::uint32_t>((_response->get_payload()->get_data())[i]);
            str.append(stream.str());
            stream.str("");
            stream.clear();
        }
        std::string str2;
        int k=1;
        for(unsigned int j = 0; j < str.length(); j+=2, k++) {
            str2.append(str.substr(j,2));
            if(k%4 == 0) {
                if(k == 4) {
                    VSOMEIP_INFO << str2 << " # payload from here on";
                } else {
                    VSOMEIP_INFO << str2;
                }
                str2.clear();
            }
        }
        VSOMEIP_INFO << "########## end message";
        VSOMEIP_INFO << "Payload as byte stream: " << str;
        str.clear();
        std::lock_guard<std::mutex> its_lock(mutex_);
        wait_for_answer_ = false;
        condition_.notify_one();
    }

    void send() {
        std::unique_lock<std::mutex> its_lock(mutex_);
        while (wait_service_available_) {
            if(std::cv_status::timeout == condition_.wait_for(its_lock, std::chrono::seconds(6))) {
                VSOMEIP_INFO << "Service [" << std::setw(4) << std::setfill('0')
                << std::hex << service_id_ << "." << instance_ << "] isn't available. Exiting";
                stop(EXIT_FAILURE);
            }
        }

        std::shared_ptr<vsomeip::message> its_message =
                vsomeip::runtime::get()->create_message(use_tcp_);
        its_message->set_method(method_id_);
        its_message->set_service(service_id_);
        its_message->set_interface_version(interface_version_);
        its_message->set_message_type(message_type_);
        its_message->set_return_code(return_code_);
        its_message->set_client(app_->get_client());
        its_message->set_instance(instance_);

        std::shared_ptr< vsomeip::payload > its_payload =
                vsomeip::runtime::get()->create_payload();
        its_payload->set_data(&user_message_[VSOMEIP_PAYLOAD_POS],
                static_cast<vsomeip::length_t>(user_message_.size() - VSOMEIP_PAYLOAD_POS));
        its_message->set_payload(its_payload);
        VSOMEIP_INFO << "Sending";
        app_->send(its_message);

        while(wait_for_answer_) {
            if(std::cv_status::timeout == condition_.wait_for(its_lock, std::chrono::seconds(5))) {
                VSOMEIP_INFO << "Didn't receive answer within 5sec. Shutting down.";
                stop(EXIT_SUCCESS);
                break;
            }
        }

        stop(EXIT_SUCCESS);
    }

private:
    bool validate_message() {
        if (!check_message_type()) {
            VSOMEIP_ERROR << "Invalid message type 0x" << std::setw(2)
                << std::setfill('0') << std::hex
                << static_cast<std::uint8_t>(message_type_) << ", exiting.";
            stop(EXIT_FAILURE);
        }

        if(!check_return_code()) {
            VSOMEIP_ERROR << "Invalid return code 0x" << std::setw(2)
                << std::setfill('0') << std::hex
                << static_cast<std::uint8_t>(return_code_) << ", exiting.";
            stop(EXIT_FAILURE);
        }

        if (service_id_ == vsomeip::sd::service &&
            method_id_ == vsomeip::sd::method) {
            VSOMEIP_ERROR << "Usage of reserved service id and method id "
                    "of service discovery, exiting.";
            stop(EXIT_FAILURE);
        }

        if (user_message_.size() != length_ + 8) {
            VSOMEIP_ERROR << "Provided length 0x" << std::setw(8)
                << std::setfill('0') << std::hex << length_
                << " doesn't match message size.";
            VSOMEIP_ERROR << "Assuming the same payload the length field should"
                    " be set to 0x" << std::setw(8) << std::setfill('0')
                    << std::hex << user_message_.size() - 8 << " , exiting.";
            stop(EXIT_FAILURE);
        }

        if (use_tcp_ && user_message_.size() > VSOMEIP_MAX_TCP_MESSAGE_SIZE) {
            VSOMEIP_WARNING << "Max allowed message size for TCP is "
                    << std::dec << VSOMEIP_MAX_TCP_MESSAGE_SIZE
                    << ". Provided message size is: " << user_message_.size();
        }
        if (!use_tcp_ && user_message_.size() > VSOMEIP_MAX_UDP_MESSAGE_SIZE) {
            VSOMEIP_WARNING << "Max allowed message size for UDP is "
                    << std::dec << VSOMEIP_MAX_UDP_MESSAGE_SIZE
                    << ". Provided message size is: " << user_message_.size();
        }
        return true;
    }

    bool check_message_type() {
        switch (message_type_) {
            case vsomeip::message_type_e::MT_REQUEST:
            case vsomeip::message_type_e::MT_REQUEST_NO_RETURN:
            case vsomeip::message_type_e::MT_NOTIFICATION:
            case vsomeip::message_type_e::MT_RESPONSE:
            case vsomeip::message_type_e::MT_ERROR:
                return true;
                break;
            case vsomeip::message_type_e::MT_UNKNOWN:
            case vsomeip::message_type_e::MT_ERROR_ACK:
            case vsomeip::message_type_e::MT_RESPONSE_ACK:
            case vsomeip::message_type_e::MT_NOTIFICATION_ACK:
            case vsomeip::message_type_e::MT_REQUEST_NO_RETURN_ACK:
            case vsomeip::message_type_e::MT_REQUEST_ACK:
            default:
                return false;
                break;
        }
    }

    bool check_return_code() {
        if (static_cast<std::uint8_t>(return_code_) > 0x3F) {
            VSOMEIP_ERROR << "Provided return code 0x" << std::setw(2)
                << std::setfill('0') << std::hex
                << static_cast<std::uint8_t>(return_code_) << " is out of range.";
            return false;
        }
        if (static_cast<std::uint8_t>(return_code_) >
            static_cast<std::uint8_t>(vsomeip::return_code_e::E_WRONG_MESSAGE_TYPE) &&
            static_cast<std::uint8_t>(return_code_) <= 0x3f) {
            VSOMEIP_ERROR << "Provided return code 0x" << std::setw(2)
                << std::setfill('0') << std::hex <<
                static_cast<std::uint8_t>(return_code_) << "is reserved.";
            return false;
        }
        switch (message_type_) {
            case vsomeip::message_type_e::MT_REQUEST:
            case vsomeip::message_type_e::MT_REQUEST_NO_RETURN:
            case vsomeip::message_type_e::MT_NOTIFICATION:
                if(return_code_ != vsomeip::return_code_e::E_OK) {
                    VSOMEIP_ERROR << "Provided return code 0x" << std::setw(2)
                        << std::setfill('0') << std::hex
                        << static_cast<std::uint8_t>(return_code_)
                        << "is invalid in combination with message type 0x"
                        << std::setw(2) << std::setfill('0') << std::hex
                        << static_cast<std::uint8_t>(message_type_)
                        << " use 0x00 (E_OK).";
                    return false;
                }
                return true;
                break;
            default:
                return true;
                break;
        }
    }

private:
    bool use_tcp_;
    std::vector<vsomeip::byte_t> user_message_;
    vsomeip::instance_t instance_;
    std::shared_ptr<vsomeip::application> app_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool wait_service_available_;
    std::thread send_thread_;
    vsomeip::service_t service_id_;
    vsomeip::method_t method_id_;
    std::uint32_t length_;
    vsomeip::client_t client_id_;
    vsomeip::interface_version_t interface_version_;
    vsomeip::message_type_e message_type_;
   vsomeip::return_code_e return_code_;
    bool wait_for_answer_;
};
} // namespace vsomeip_ctrl

static void print_help(char* binary_name) {
    std::cout << "Usage example:" << std::endl;
    std::cout << binary_name << " --instance 5678 "
            << "--message 123480e800000015134300030100000000000009efbbbf576f726c6400\n"
            << "This will send a message to service with service id 1234 and instance 5678."
            << std::endl << std::endl;
    std::cout <<
    "Available options:\n"
    "--help     | -h : print this help\n"
    "--instance | -i : instance id of target service in hex (required)\n"
    "--tcp      | -t : flag to enable sending over TCP, default off (= UDP)\n"
    "--message  | -m : vSomeIP message to send in hex (required)\n\n"
    "Please note: the fields client id and session id in the provided message\n"
    "will be overwritten by the stack with the required values\n"
    "Please further make sure to use the same configuration file\n"
    "as the target service, if the system is not using routingmanagerd" << std::endl;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "To few arguments, please see the help with : "
                << argv[0] << " --help" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<vsomeip::byte_t> user_message;
    vsomeip::instance_t instance(vsomeip::ANY_INSTANCE);
    bool use_tcp(false);

    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        } else if (arg == "--message" || arg == "-m") {
            std::string message(argv[i + 1]);
            for (unsigned int i = 0; i < message.length(); i += 2) {
                vsomeip::byte_t its_byte;
                try {
                    std::uint64_t tmp = std::stoul(message.substr(i, 2), 0, 16);
                    tmp = (tmp > (std::numeric_limits<std::uint8_t>::max)()) ?
                            (std::numeric_limits<std::uint8_t>::max)() : tmp;
                    its_byte = static_cast<vsomeip::byte_t>(tmp);
                } catch (std::invalid_argument &e) {
                    std::cerr << e.what() << ": Couldn't convert '"
                            << message.substr(i, 2) << "' to hex, exiting: "
                            << std::endl;
                    exit(EXIT_FAILURE);
                }
                user_message.push_back(its_byte);
            }
        } if (arg == "--tcp" || arg == "-t") {
            use_tcp = true;
        } else if (arg == "--instance" || arg == "-i") {
            std::string instance_str(argv[i + 1]);
            if(instance_str.length() > 4) {
                std::cerr << "provided instance is to long, exiting." << std::endl;
                exit(EXIT_FAILURE);
            }
            if(instance_str.length() < 4) {
                while(instance_str.size() != 4) {
                    instance_str = std::string("0") += instance_str;
                }
            }
            vsomeip::byte_t high(0x0);
            vsomeip::byte_t low(0x0);
            std::cout << "Instance: " << instance_str << std::endl;
            for (unsigned int i = 0; i < instance_str.length(); i += 2) {
                try {
                    std::uint64_t tmp = std::stoul(instance_str.substr(i, 2), 0, 16);
                    tmp = (tmp > (std::numeric_limits<std::uint8_t>::max)()) ?
                            (std::numeric_limits<std::uint8_t>::max)() : tmp;

                    vsomeip::byte_t its_byte = static_cast<vsomeip::byte_t>(tmp);
                    if (i == 0) {
                        high = its_byte;
                    } else {
                        low = its_byte;
                    }
                } catch (std::invalid_argument &e) {
                    std::cerr << e.what() << ": Couldn't convert '"
                            << instance_str.substr(i, 2) << "' to hex, exiting: "
                            << std::endl;
                    exit(EXIT_FAILURE);
                }
            }
            uint8_t its_instance[2] = {high, low};
            instance = vsomeip::bithelper::read_uint16_be(its_instance);
        }
    }

    if(instance == vsomeip::ANY_INSTANCE) {
        std::cerr << "Please provide a target instance (see --help)" << std::endl;
        exit(EXIT_FAILURE);
    }

    if(user_message.empty()) {
        std::cerr << "Please provide a message to send (see --help)" << std::endl;
        exit(EXIT_FAILURE);
    }

    vsomeip_ctrl::vsomeip_sender sender(use_tcp, user_message, instance);
    return EXIT_SUCCESS;
}
