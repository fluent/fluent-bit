// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>
#include <memory>
#include <thread>
#include <chrono>
#include <cstring>
#include <future>
#include <numeric>
#include <random>
#include <algorithm>
#include <list>

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
#include <arpa/inet.h>
#endif

#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include <vsomeip/vsomeip.hpp>

#include "../../implementation/utility/include/bithelper.hpp"
#include "../../implementation/message/include/deserializer.hpp"
#include "../../implementation/message/include/serializer.hpp"
#include "../../implementation/service_discovery/include/service_discovery.hpp"
#include "../../implementation/service_discovery/include/message_impl.hpp"
#include "../../implementation/service_discovery/include/constants.hpp"
#include "../../implementation/service_discovery/include/enumeration_types.hpp"
#include "../../implementation/service_discovery/include/eventgroupentry_impl.hpp"
#include "../../implementation/service_discovery/include/serviceentry_impl.hpp"
#include "../../implementation/message/include/message_impl.hpp"
#include "../../implementation/service_discovery/include/option_impl.hpp"
#include "../../implementation/service_discovery/include/ipv4_option_impl.hpp"
#include "../../implementation/endpoints/include/tp.hpp"
#include "../../implementation/endpoints/include/tp_reassembler.hpp"
#include "../../implementation/message/include/payload_impl.hpp"

#include "someip_tp_test_globals.hpp"

static char* remote_address;
static char* local_address;

std::vector<someip_tp_test::test_mode_e> its_modes({
    someip_tp_test::test_mode_e::IN_SEQUENCE,
    someip_tp_test::test_mode_e::MIXED,
    someip_tp_test::test_mode_e::INCOMPLETE,
    someip_tp_test::test_mode_e::DUPLICATE,
    someip_tp_test::test_mode_e::OVERLAP,
    someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK,
});

class someip_tp : public ::testing::TestWithParam<someip_tp_test::test_mode_e> {
public:
    someip_tp() :
        work_(std::make_shared<boost::asio::io_context::work>(io_)),
        io_thread_(std::bind(&someip_tp::io_run, this)),
        session_(0x0),
        sd_session_(0x0),
        address_remote_(boost::asio::ip::address::from_string(std::string(remote_address))),
        address_local_(boost::asio::ip::address::from_string(std::string(local_address))),
        runtime_(vsomeip::runtime::get()) {}
protected:
    void TearDown() {
        work_.reset();
        io_thread_.join();
        io_.stop();
    }

    void call_shutdown_method() {
        boost::system::error_code ec;
        std::uint8_t shutdown_call[] = {
            0x45, 0x45, 0x45, 0x01,
            0x00, 0x00, 0x00, 0x08,
            0xDD, 0xDD, 0x00, 0x01,
            0x01, 0x00, 0x00, 0x00 };
        boost::asio::ip::udp::socket::endpoint_type target_service(address_remote_,
                30001);
        boost::asio::ip::udp::socket udp_socket2(io_, boost::asio::ip::udp::v4());
        udp_socket2.send_to(boost::asio::buffer(shutdown_call), target_service);
        udp_socket2.shutdown(boost::asio::socket_base::shutdown_both, ec);
        udp_socket2.close(ec);
    }

    void io_run() {
        io_.run();
    }

    void offer_service(boost::asio::ip::udp::socket* const _udp_socket) {
        // offer the service
        std::uint8_t its_offer_service_message[] = {
            0xff, 0xff, 0x81, 0x00,
            0x00, 0x00, 0x00, 0x30, // length
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0x02, 0x00,
            0xc0, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, // length entries array
            0x01, 0x00, 0x00, 0x20,
            0x67, 0x67, 0x00, 0x01, // service / instance
            0x00, 0xff, 0xff, 0xff, // major / ttl
            0x00, 0x00, 0x00, 0x00, // minor
            0x00, 0x00, 0x00, 0x0c, // length options array
            0x00, 0x09, 0x04, 0x00,
            0xff, 0xff, 0xff, 0xff, // slave address
            0x00, 0x11, 0x9c, 0x41,
        };
        std::memcpy(&its_offer_service_message[48], &address_local_.to_v4().to_bytes()[0], 4);
        std::uint16_t its_session = htons(++sd_session_);
        std::memcpy(&its_offer_service_message[10], &its_session, sizeof(its_session));

        boost::asio::ip::udp::socket::endpoint_type target_sd(address_remote_,30490);
        _udp_socket->send_to(boost::asio::buffer(its_offer_service_message), target_sd);
    }

    void subscribe_at_master(boost::asio::ip::udp::socket* const _udp_socket) {
        std::uint8_t its_subscription[] = {
            0xff, 0xff, 0x81, 0x00,
            0x00, 0x00, 0x00, 0x30, // length
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0x02, 0x00,
            0xc0, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, // length entries array
            0x06, 0x00, 0x00, 0x10,
            0x45, 0x45, 0x00, 0x01, // service / instance
            0x00, 0xff, 0xff, 0xff, // major / ttl
            0x00, 0x00, 0x00, 0x01, // counter
            0x00, 0x00, 0x00, 0x0c, // length options array
            0x00, 0x09, 0x04, 0x00,
            0xff, 0xff, 0xff, 0xff, // slave address
            0x00, 0x11, 0x75, 0x31, // port 30001
        };
        std::memcpy(&its_subscription[48], &address_local_.to_v4().to_bytes()[0], 4);
        std::uint16_t its_session = htons(++sd_session_);
        std::memcpy(&its_subscription[10], &its_session, sizeof(its_session));

        boost::asio::ip::udp::socket::endpoint_type target_sd(address_remote_,30490);
        _udp_socket->send_to(boost::asio::buffer(its_subscription), target_sd);
    }

    /*
     * @brief custom version of tp::tp_split_message with adjustable segment size
     * needed to send overlapping segments within the 1392 byte segment size limit
     */
    vsomeip::tp::tp_split_messages_t split_message(const std::uint8_t * const _data,
                                             std::uint32_t _size , std::uint32_t _segment_size) {
        using namespace vsomeip::tp;
        using namespace vsomeip;
        tp_split_messages_t split_messages;

        if (_size < VSOMEIP_MAX_UDP_MESSAGE_SIZE) {
            std::cerr << __func__ << " called with size: " << std::dec << _size;
            return split_messages;
        }

        const auto data_end = _data + _size;

        for (auto current_offset = _data + 16; current_offset < data_end;) {
            auto msg = std::make_shared<message_buffer_t>();
            msg->reserve(VSOMEIP_FULL_HEADER_SIZE + sizeof(tp_header_t) + _segment_size);
            // copy the header
            msg->insert(msg->end(), _data, _data + VSOMEIP_FULL_HEADER_SIZE);
            // change the message type
            (*msg)[VSOMEIP_MESSAGE_TYPE_POS] = (*msg)[VSOMEIP_MESSAGE_TYPE_POS] | 0x20;
            // check if last segment
            const auto segment_end = current_offset + _segment_size;
            const bool is_last_segment = (segment_end >= data_end);
            // insert tp_header
            const tp_header_t header = htonl(
                    static_cast<tp_header_t>((current_offset - VSOMEIP_FULL_HEADER_SIZE - _data)) |
                    static_cast<tp_header_t>((is_last_segment) ? 0x0u : 0x1u));

            const byte_t * const headerp = reinterpret_cast<const byte_t*>(&header);
            msg->insert(msg->end(), headerp, headerp + sizeof(tp_header_t));

            // insert payload
            if (is_last_segment) {
                msg->insert(msg->end(), current_offset, data_end);
                current_offset = data_end;
            } else {
                msg->insert(msg->end(), current_offset, segment_end);
                current_offset += _segment_size;
            }
            // update length
            const length_t its_length = static_cast<length_t>(msg->size()
                                                    - VSOMEIP_SOMEIP_HEADER_SIZE);
            *(reinterpret_cast<length_t*>(&(*msg)[VSOMEIP_LENGTH_POS_MIN])) = htonl(its_length);
            split_messages.emplace_back(std::move(msg));
        }

        return split_messages;
    }

    void create_fragments(std::uint32_t _count, vsomeip::service_t _service,
                          vsomeip::instance_t _instance,
                          vsomeip::method_t _method,
                          vsomeip::message_type_e _message_type,
                          vsomeip::client_t _client,
                          vsomeip::session_t _session,
                          std::vector<vsomeip::message_buffer_ptr_t>* _target,
                          std::uint32_t _segment_size) {
        vsomeip::message_impl msg;
        msg.set_reliable(false);
        msg.set_service(_service);
        msg.set_instance(_instance);
        msg.set_method(_method);
        msg.set_message_type(_message_type);
        msg.set_return_code(vsomeip::return_code_e::E_OK);
        if (_client == vsomeip::ANY_CLIENT) {
            msg.set_client(0xDDDD);
        } else {
            msg.set_client(_client);
        }
        if (_session == 0xFFFF) {
            msg.set_session(++session_);
        } else {
            msg.set_session(_session);
        }
        std::vector<vsomeip::byte_t> its_payload_data;
        for (uint32_t i = 0; i < _count; i++) {
            its_payload_data.resize((i * _segment_size) + _segment_size, static_cast<std::uint8_t>(i));
        }
        std::shared_ptr<vsomeip::payload> payload = std::make_shared<vsomeip::payload_impl>(its_payload_data);
        msg.set_payload(payload);
        vsomeip::serializer its_serializer(0);
        msg.serialize(&its_serializer);

        *_target = split_message(its_serializer.get_data(), its_serializer.get_size(), _segment_size);
        its_serializer.reset();

    }

    vsomeip::message_buffer_t create_full_message(
            const std::vector<vsomeip::message_buffer_ptr_t>& _fragments) {
        auto its_reassembler = std::make_shared<vsomeip::tp::tp_reassembler>(
                std::numeric_limits<std::uint32_t>::max(), io_);
        vsomeip::message_buffer_t its_reassemlbed_msg;
        for (const auto& frag : _fragments) {
            const auto res =  its_reassembler->process_tp_message(&(*frag)[0],
                    std::uint32_t(frag->size()), address_local_, 12345);
            if (res.first) {
                its_reassemlbed_msg = res.second;
            }
        }
        its_reassembler->stop();
        return its_reassemlbed_msg;
    }

    std::vector<int> create_shuffled_seqeuence(std::uint32_t _count) {
        std::vector<int> its_indexes(_count);
        std::iota(its_indexes.begin(), its_indexes.end(), 0);
        std::random_device rd;
        std::mt19937 its_twister(rd());
        std::shuffle(its_indexes.begin(), its_indexes.end(), its_twister);
        return its_indexes;
    }
    void increase_segment_back(const vsomeip::message_buffer_ptr_t& _seg,
                                     std::uint32_t _amount) {
        _seg->resize(_seg->size() + _amount, 0xff);
        // update length
        *(reinterpret_cast<vsomeip::length_t*>(&((*_seg)[VSOMEIP_LENGTH_POS_MIN]))) =
                htonl(static_cast<vsomeip::length_t>(_seg->size() - VSOMEIP_SOMEIP_HEADER_SIZE));
    }

    void increase_segment_front(const vsomeip::message_buffer_ptr_t& _seg,
                                     std::uint32_t _amount) {
        // increase segment by amount
        _seg->insert(_seg->begin() + VSOMEIP_TP_PAYLOAD_POS, _amount, 0xff);

        // decrease offset by amount
        const vsomeip::tp::tp_header_t its_tp_header = vsomeip::bithelper::read_uint32_be(&(*_seg)[VSOMEIP_TP_HEADER_POS_MIN]);
        std::uint32_t its_offset = vsomeip::tp::tp::get_offset(its_tp_header);
        its_offset -= _amount;
        const vsomeip::tp::tp_header_t its_new_tp_header =
                htonl(static_cast<vsomeip::tp::tp_header_t>(its_offset |
                        static_cast<vsomeip::tp::tp_header_t>(its_tp_header & 0x1)));
        *(reinterpret_cast<vsomeip::tp::tp_header_t*>(
                &((*_seg)[VSOMEIP_TP_HEADER_POS_MIN]))) = its_new_tp_header;

        // update length
        *(reinterpret_cast<vsomeip::length_t*>(&((*_seg)[VSOMEIP_LENGTH_POS_MIN]))) =
                htonl(static_cast<vsomeip::length_t>(_seg->size() - VSOMEIP_SOMEIP_HEADER_SIZE));
    }

    void increase_segment_front_back(const vsomeip::message_buffer_ptr_t& _seg,
                                     std::uint32_t _amount) {
        increase_segment_front(_seg, _amount);
        increase_segment_back(_seg, _amount);
    }

    void decrease_segment_back(const vsomeip::message_buffer_ptr_t& _seg,
                                     std::uint32_t _amount) {
        _seg->resize(_seg->size() - _amount, 0xff);
        // update length
        *(reinterpret_cast<vsomeip::length_t*>(&((*_seg)[VSOMEIP_LENGTH_POS_MIN]))) =
                htonl(static_cast<vsomeip::length_t>(_seg->size() - VSOMEIP_SOMEIP_HEADER_SIZE));
    }

    void decrease_segment_front(const vsomeip::message_buffer_ptr_t& _seg,
                                     std::uint32_t _amount) {
        if (_amount % 16 != 0) {
            std::cerr << __func__ << ":" << __LINE__ << std::endl;
            return;
        }
        _seg->erase(_seg->begin() + VSOMEIP_TP_PAYLOAD_POS, _seg->begin() + VSOMEIP_TP_PAYLOAD_POS + _amount);
        // increase offset by amount
        const vsomeip::tp::tp_header_t its_tp_header = vsomeip::bithelper::read_uint32_be(&(*_seg)[VSOMEIP_TP_HEADER_POS_MIN]);
        std::uint32_t its_offset = vsomeip::tp::tp::get_offset(its_tp_header);
        its_offset += _amount;
        const vsomeip::tp::tp_header_t its_new_tp_header =
                htonl(static_cast<vsomeip::tp::tp_header_t>(its_offset |
                        static_cast<vsomeip::tp::tp_header_t>(its_tp_header & 0x1)));
        *(reinterpret_cast<vsomeip::tp::tp_header_t*>(
                &((*_seg)[VSOMEIP_TP_HEADER_POS_MIN]))) = its_new_tp_header;
        // update length
        *(reinterpret_cast<vsomeip::length_t*>(&((*_seg)[VSOMEIP_LENGTH_POS_MIN]))) =
                htonl(static_cast<vsomeip::length_t>(_seg->size() - VSOMEIP_SOMEIP_HEADER_SIZE));
    }

    void decrease_segment_front_back(const vsomeip::message_buffer_ptr_t& _seg,
                                     std::uint32_t _amount) {
        if (_amount % 16 != 0) {
            std::cerr << __func__ << ":" << __LINE__ << std::endl;
            return;
        }
        decrease_segment_back(_seg, _amount);
        decrease_segment_front(_seg, _amount);
    }


    enum order_e {
        ASCENDING,
        DESCENDING,
        MIXED_PREDEFINED,
        MIXED_RANDOM,
    };

    boost::asio::io_context io_;
    std::shared_ptr<boost::asio::io_context::work> work_;
    std::thread io_thread_;
    std::vector<vsomeip::message_buffer_ptr_t> fragments_request_to_master_;
    std::vector<vsomeip::message_buffer_ptr_t> fragments_response_of_master_;

    std::vector<vsomeip::message_buffer_ptr_t> fragments_received_as_server_;
    std::vector<vsomeip::message_buffer_ptr_t> fragments_response_to_master_;

    std::vector<vsomeip::message_buffer_ptr_t> fragments_event_from_master_;
    std::vector<vsomeip::message_buffer_ptr_t> fragments_event_to_master_;

    std::atomic<std::uint16_t> session_;
    std::atomic<std::uint16_t> sd_session_;
    boost::asio::ip::address address_remote_;
    boost::asio::ip::address address_local_;
    std::shared_ptr<vsomeip::runtime> runtime_;
    someip_tp_test::test_mode_e test_mode_ = GetParam();
};

INSTANTIATE_TEST_CASE_P(send_in_mode,
                        someip_tp,
                        ::testing::ValuesIn(its_modes));


/*
 * @test Send a big fragmented UDP request to the master and wait for the
 * response. Check that the received response is the same as the request (server
 * just echos the requests).
 * Wait for a big fragmented UDP message request from the master and send back
 * the response in the same size. Check that the request and response are
 * identical.
 * Do this two times one with fragments ordered ascending and one time descending.
 * Wait for the master to subscribe and send back two big, fragmented
 * notifications one with fragments ordered ascending and one descending
 * Subscribe at master and wait for one fragmented event.
 * With testmode INCOMPLETE incomplete fragments are send as well
 * With testmode MIXED instead of ascending/descedning order the fragments are
 * send in a predefined or in a random order
 */
TEST_P(someip_tp, send_in_mode)
{
    std::promise<void> remote_client_subscribed;
    std::atomic<std::uint16_t> remote_client_subscription_port(0);
    std::promise<void> offer_received;

    std::mutex udp_sd_socket_mutex;
    boost::asio::ip::udp::socket udp_sd_socket(io_,
            boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 30490));

    boost::asio::ip::udp::socket udp_client_socket(io_,
            boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 30001));

    boost::asio::ip::udp::socket udp_server_socket(io_,
            boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 40001));

    std::thread sd_receive_thread([&](){
        std::atomic<bool> keep_receiving(true);
        std::vector<std::uint8_t> receive_buffer(4096);
        std::vector<vsomeip::event_t> its_received_events;
        std::atomic<bool> service_offered(false);
        std::atomic<bool> client_subscribed(false);

        // join the sd multicast group 224.0.77.1
        udp_sd_socket.set_option(boost::asio::ip::multicast::join_group(
                            boost::asio::ip::address::from_string("224.0.77.1").to_v4()));
        while (keep_receiving) {
            boost::system::error_code error;
            std::size_t bytes_transferred = udp_sd_socket.receive(
                        boost::asio::buffer(receive_buffer, receive_buffer.capacity()), 0, error);
            if (error) {
                keep_receiving = false;
                ADD_FAILURE() << __func__ << " error: " << error.message();
                return;
            } else {
                vsomeip::deserializer its_deserializer(&receive_buffer[0], bytes_transferred, 0);
                vsomeip::service_t its_service = vsomeip::bithelper::read_uint16_be(&receive_buffer[VSOMEIP_SERVICE_POS_MIN]);
                vsomeip::method_t its_method   = vsomeip::bithelper::read_uint16_be(&receive_buffer[VSOMEIP_METHOD_POS_MIN]);

                if (its_service == vsomeip::sd::service && its_method == vsomeip::sd::method) {
                    vsomeip::sd::message_impl sd_msg;
                    EXPECT_TRUE(sd_msg.deserialize(&its_deserializer));
                    EXPECT_EQ(1u, sd_msg.get_entries().size());
                    for (const auto& e : sd_msg.get_entries()) {
                        if (e->get_type() == vsomeip::sd::entry_type_e::SUBSCRIBE_EVENTGROUP && !client_subscribed) {
                            EXPECT_TRUE(e->is_eventgroup_entry());
                            EXPECT_EQ(vsomeip::sd::entry_type_e::SUBSCRIBE_EVENTGROUP, e->get_type());
                            EXPECT_EQ(1,e->get_num_options(1));
                            EXPECT_EQ(std::uint32_t(0xFFFFFF), e->get_ttl());
                            EXPECT_EQ(someip_tp_test::service_slave.service_id, e->get_service());
                            EXPECT_EQ(someip_tp_test::service_slave.instance_id, e->get_instance());
                            EXPECT_EQ(1u, sd_msg.get_options().size());
                            if (e->get_type() == vsomeip::sd::entry_type_e::SUBSCRIBE_EVENTGROUP) {
                                std::shared_ptr<vsomeip::sd::eventgroupentry_impl> its_casted_entry =
                                        std::static_pointer_cast<vsomeip::sd::eventgroupentry_impl>(e);
                                EXPECT_EQ(someip_tp_test::service_slave.eventgroup_id,
                                          its_casted_entry->get_eventgroup());
                                std::shared_ptr<vsomeip::sd::option_impl> its_option =
                                        sd_msg.get_options().at(its_casted_entry->get_options(1)[0]);
                                EXPECT_TRUE(its_option > 0);
                                if(its_option->get_type() == vsomeip::sd::option_type_e::IP4_ENDPOINT) {
                                    std::shared_ptr<vsomeip::sd::ipv4_option_impl> its_ipv4_option =
                                            std::dynamic_pointer_cast<vsomeip::sd::ipv4_option_impl> (its_option);
                                    EXPECT_TRUE(its_ipv4_option > 0);
                                    EXPECT_EQ(vsomeip::sd::layer_four_protocol_e::UDP, its_ipv4_option->get_layer_four_protocol());
                                    EXPECT_EQ(address_remote_,
                                              boost::asio::ip::address(
                                                      boost::asio::ip::address_v4(its_ipv4_option->get_address())));
                                    remote_client_subscription_port = its_ipv4_option->get_port();
                                }
                                std::vector<vsomeip::byte_t> its_sub_ack(&receive_buffer[0], &receive_buffer[0] + VSOMEIP_FULL_HEADER_SIZE + 8 + (sd_msg.get_entries().size() * 16));
                                its_sub_ack[24] = static_cast<vsomeip::byte_t>(vsomeip::sd::entry_type_e::SUBSCRIBE_EVENTGROUP_ACK);
                                // fix length
                                const std::uint32_t its_length = htonl(static_cast<std::uint32_t>(its_sub_ack.size()) - VSOMEIP_SOMEIP_HEADER_SIZE);
                                std::memcpy(&its_sub_ack[4], &its_length, sizeof(its_length));
                                // set number of options to zero
                                its_sub_ack[27] = 0x0;
                                // update session
                                std::uint16_t its_session = htons(++sd_session_);
                                std::memcpy(&its_sub_ack[10], &its_session, sizeof(its_session));
                                boost::asio::ip::udp::socket::endpoint_type target_sd(address_remote_,30490);
                                {
                                    std::lock_guard<std::mutex> its_lock(udp_sd_socket_mutex);
                                    udp_sd_socket.send_to(boost::asio::buffer(its_sub_ack), target_sd);
                                }
                                std::cout << __LINE__ << ": master subscribed" << std::endl;
                                remote_client_subscribed.set_value();
                                client_subscribed = true;
                            }
                        } else if (e->get_type() == vsomeip::sd::entry_type_e::OFFER_SERVICE && !service_offered) {
                            EXPECT_TRUE(e->is_service_entry());
                            EXPECT_EQ(vsomeip::sd::entry_type_e::OFFER_SERVICE, e->get_type());
                            EXPECT_EQ(1u,e->get_num_options(1));
                            EXPECT_EQ(std::uint32_t(0xFFFFFF), e->get_ttl());
                            EXPECT_EQ(someip_tp_test::service.service_id, e->get_service());
                            EXPECT_EQ(someip_tp_test::service.instance_id, e->get_instance());
                            EXPECT_EQ(1u, sd_msg.get_options().size());
                            if (e->get_type() == vsomeip::sd::entry_type_e::OFFER_SERVICE) {
                                std::shared_ptr<vsomeip::sd::serviceentry_impl> its_casted_entry =
                                        std::static_pointer_cast<vsomeip::sd::serviceentry_impl>(e);
                                EXPECT_EQ(0u, its_casted_entry->get_minor_version());
                            }
                            offer_received.set_value();
                            service_offered = true;
                        }
                    }
                    if (service_offered && client_subscribed) {
                        keep_receiving = false;
                    }
                } else {
                    ADD_FAILURE() << " received non-sd message";
                    return;
                }
            }
        }
    });

    std::thread send_thread([&]() {
        boost::system::error_code ec;
        try {

            // wait until a offer was received
            if (std::future_status::timeout == offer_received.get_future().wait_for(std::chrono::seconds(10))) {
                ADD_FAILURE() << "Didn't receive offer within time";
                return;
            }

            {
                std::lock_guard<std::mutex> its_lock(udp_sd_socket_mutex);
                subscribe_at_master(&udp_sd_socket);
            }

            std::mutex all_fragments_received_mutex_;
            std::condition_variable all_fragments_received_cond_;
            bool wait_for_all_response_fragments_received_(true);
            std::uint32_t received_responses(0);
            bool wait_for_all_event_fragments_received_(true);

            std::thread udp_client_receive_thread([&]() {
                bool keep_receiving(true);
                std::vector<std::uint8_t> receive_buffer(4096);
                while (keep_receiving) {
                    boost::system::error_code error;
                    std::size_t bytes_transferred = udp_client_socket.receive(
                            boost::asio::buffer(receive_buffer, receive_buffer.capacity()), 0, error);
                    if (error) {
                        keep_receiving = false;
                        ADD_FAILURE() << __func__ << " error: " << error.message();
                        return;
                    } else {
                        std::uint32_t its_pos = 0;

                        while (bytes_transferred > 0) {
                            const std::uint32_t its_message_size = vsomeip::bithelper::read_uint32_be(
                                                                    &receive_buffer[its_pos + VSOMEIP_LENGTH_POS_MIN])
                                                                    + VSOMEIP_SOMEIP_HEADER_SIZE;

                            std::cout << __LINE__ << ": received response " << its_message_size << std::endl;

                            vsomeip::deserializer its_deserializer(&receive_buffer[its_pos], its_message_size, 0);
                            vsomeip::service_t its_service = vsomeip::bithelper::read_uint16_be(&receive_buffer[its_pos + VSOMEIP_SERVICE_POS_MIN]);
                            vsomeip::method_t its_method   = vsomeip::bithelper::read_uint16_be(&receive_buffer[its_pos + VSOMEIP_METHOD_POS_MIN]);

                            vsomeip::message_impl msg;
                            EXPECT_TRUE(msg.deserialize(&its_deserializer));
                            if (msg.get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
                                EXPECT_EQ(vsomeip::message_type_e::MT_RESPONSE, msg.get_message_type());
                                EXPECT_EQ(someip_tp_test::service.service_id, msg.get_service());
                            } else if (msg.get_message_type() == vsomeip::message_type_e::MT_NOTIFICATION) {
                                std::cout << __LINE__ << ": received event" << std::endl;
                            } else if (vsomeip::tp::tp::tp_flag_is_set(receive_buffer[its_pos + VSOMEIP_MESSAGE_TYPE_POS]) &&
                                       vsomeip::tp::tp::tp_flag_unset(receive_buffer[its_pos + VSOMEIP_MESSAGE_TYPE_POS]) == vsomeip::message_type_e::MT_RESPONSE) {
                                EXPECT_EQ(someip_tp_test::service.service_id, its_service);
                                EXPECT_EQ(someip_tp_test::service.method_id, its_method);
                                auto its_buffer = std::make_shared<vsomeip::message_buffer_t>(&receive_buffer[its_pos], &receive_buffer[its_pos] + its_message_size);

                                fragments_response_of_master_.push_back(its_buffer);
                                if (fragments_response_of_master_.size() == someip_tp_test::number_of_fragments) {
                                    std::lock_guard<std::mutex> its_lock(all_fragments_received_mutex_);
                                    wait_for_all_response_fragments_received_ = false;
                                    std::cout << __LINE__ << ": received all response fragments as client" << std::endl;
                                    all_fragments_received_cond_.notify_one();
                                    if (++received_responses == 2 && !wait_for_all_event_fragments_received_) {
                                        std::cout << __LINE__ << ": received all responses as client --> Finished" << std::endl;
                                        keep_receiving = false;
                                    }
                                }
                            } else if (vsomeip::tp::tp::tp_flag_is_set(receive_buffer[its_pos + VSOMEIP_MESSAGE_TYPE_POS]) &&
                                    vsomeip::tp::tp::tp_flag_unset(receive_buffer[its_pos + VSOMEIP_MESSAGE_TYPE_POS]) == vsomeip::message_type_e::MT_NOTIFICATION) {
                                std::cout << __LINE__ << ": received event fragment" << std::endl;
                                EXPECT_EQ(someip_tp_test::service.service_id, its_service);
                                EXPECT_EQ(someip_tp_test::service.event_id, its_method);
                                auto its_buffer = std::make_shared<vsomeip::message_buffer_t>(&receive_buffer[its_pos], &receive_buffer[its_pos] + its_message_size);
                                fragments_event_from_master_.push_back(its_buffer);
                                if (fragments_event_from_master_.size() == someip_tp_test::number_of_fragments) {
                                    std::lock_guard<std::mutex> its_lock(all_fragments_received_mutex_);
                                    wait_for_all_event_fragments_received_ = false;
                                    std::cout << __LINE__ << ": received all event fragments as client --> Finished" << std::endl;
                                    all_fragments_received_cond_.notify_one();
                                    if (received_responses == 2) {
                                        keep_receiving = false;
                                    }
                                }

                            }
                            its_pos += its_message_size;
                            bytes_transferred -= its_message_size;
                        }
                    }
                }
            });

            // send SOMEI-TP message fragmented into 6 parts to service:
            boost::asio::ip::udp::socket::endpoint_type target_service(address_remote_, 30001);

            std::unique_lock<std::mutex> its_lock(all_fragments_received_mutex_);
            for (const order_e mode : {order_e::ASCENDING, order_e::DESCENDING}) {
                create_fragments(someip_tp_test::number_of_fragments, someip_tp_test::service.service_id,
                        someip_tp_test::service.instance_id,
                        someip_tp_test::service.method_id,
                        vsomeip::message_type_e::MT_REQUEST,
                        vsomeip::ANY_CLIENT, 0xffff,
                        &fragments_request_to_master_,
                        (test_mode_ == someip_tp_test::test_mode_e::OVERLAP ||
                            test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) ?
                                vsomeip::tp::tp::tp_max_segment_length_ - 160 :
                                vsomeip::tp::tp::tp_max_segment_length_);
                if (mode == order_e::ASCENDING) {
                    if (test_mode_ == someip_tp_test::test_mode_e::MIXED) {
                        if (someip_tp_test::number_of_fragments != 6) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        } else {
                            auto its_indexes = {4, 1, 3, 5, 2, 0};
                            std::cout << __LINE__ << ": using following predefined sequence to send request to master: ";
                            for (auto i : its_indexes) { std::cout << i << ", "; }
                            std::cout << std::endl;
                            for (int i : its_indexes) {
                                udp_client_socket.send_to(boost::asio::buffer(*fragments_request_to_master_[i]), target_service);
                            }
                        }
                    } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                        if (someip_tp_test::number_of_fragments != 6) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                        } else {
                            auto its_indexes = {0,1,3,5,2,4};
                            std::cout << __LINE__ << ": using following predefined sequence to send request to master: ";
                            for (auto i : its_indexes) { std::cout << i << ", "; }
                            std::cout << std::endl;
                            // increase third segment by 16 byte at front and back
                            increase_segment_front_back(fragments_request_to_master_[2], 16);
                            increase_segment_front(fragments_request_to_master_[4], 16);
                            for (int i : its_indexes) {
                                udp_client_socket.send_to(boost::asio::buffer(*fragments_request_to_master_[i]), target_service);
                            }
                        }
                    } else if (test_mode_ == someip_tp_test::test_mode_e::DUPLICATE) {
                        if (someip_tp_test::number_of_fragments < 2) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        }
                        for (auto iter = fragments_request_to_master_.begin();
                                iter != fragments_request_to_master_.end(); iter++) {
                            udp_client_socket.send_to(boost::asio::buffer(*(*iter)), target_service);
                            // send insert 2nd fragment twice
                            if (iter == fragments_request_to_master_.begin() + 1) {
                                udp_client_socket.send_to(boost::asio::buffer(*(*iter)), target_service);
                            }
                        }
                    } else {
                        if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
                            if (someip_tp_test::number_of_fragments < 3) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                return;
                            }
                            // send a request fragment with a different session ID first
                            vsomeip::message_buffer_t msg_incomplete(*fragments_request_to_master_[2]);
                            msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0x33;
                            msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0x33;
                            udp_client_socket.send_to(boost::asio::buffer(msg_incomplete), target_service);
                            // send a request from a different src port as well to test cleanup
                            boost::asio::ip::udp::socket udp_client_socket2(io_,
                                    boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 30004));
                            msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0xcc;
                            msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0xcc;
                            udp_client_socket2.send_to(boost::asio::buffer(msg_incomplete), target_service);
                            boost::system::error_code ec;
                            udp_client_socket2.shutdown(boost::asio::socket_base::shutdown_both, ec);
                            udp_client_socket2.close(ec);
                        } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                            if (someip_tp_test::number_of_fragments < 2) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                return;
                            }
                            increase_segment_back(fragments_request_to_master_[1], 16);
                        }
                        for (const auto& fragment : fragments_request_to_master_) {
                            udp_client_socket.send_to(boost::asio::buffer(*fragment), target_service);
                        }
                    }
                } else if (mode == order_e::DESCENDING) {
                    if (test_mode_ == someip_tp_test::test_mode_e::MIXED) {
                        std::vector<int> its_indexes = create_shuffled_seqeuence(someip_tp_test::number_of_fragments);
                        std::cout << __LINE__ << ": using following random sequence to send request to master: ";
                        for (auto i : its_indexes) { std::cout << i << ", "; }
                        std::cout << std::endl;
                        for (int i : its_indexes) {
                            udp_client_socket.send_to(boost::asio::buffer(*fragments_request_to_master_[i]), target_service);
                        }
                    } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                        if (someip_tp_test::number_of_fragments != 6) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                        } else {
                            auto its_indexes = {5,3,2,4,1,0};
                            std::cout << __LINE__ << ": using following predefined sequence to send request to master: ";
                            for (auto i : its_indexes) { std::cout << i << ", "; }
                            std::cout << std::endl;
                            // increase third segment by 16 byte at front and back
                            increase_segment_front_back(fragments_request_to_master_[4], 16);
                            for (int i : its_indexes) {
                                udp_client_socket.send_to(boost::asio::buffer(*fragments_request_to_master_[i]), target_service);
                            }
                        }
                    } else if (test_mode_ == someip_tp_test::test_mode_e::DUPLICATE) {
                        if (someip_tp_test::number_of_fragments < 2) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        }
                        for (auto iter = fragments_request_to_master_.rbegin();
                                iter != fragments_request_to_master_.rend(); iter++) {
                            udp_client_socket.send_to(boost::asio::buffer(*(*iter)), target_service);
                            // send insert 2nd last fragment twice
                            if (iter == fragments_request_to_master_.rbegin() + 1) {
                                udp_client_socket.send_to(boost::asio::buffer(*(*iter)), target_service);
                            }
                        }
                    } else {
                        if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
                            if (someip_tp_test::number_of_fragments < 4) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                return;
                            }
                            // send a request fragment with a different session ID first
                            vsomeip::message_buffer_t msg_incomplete(*fragments_request_to_master_[3]);
                            msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0x77;
                            msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0x77;
                            udp_client_socket.send_to(boost::asio::buffer(msg_incomplete), target_service);

                            // send a request from a different src port as well to test cleanup
                            boost::asio::ip::udp::socket udp_client_socket2(io_,
                                    boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 30005));
                            msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0xdd;
                            msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0xdd;
                            udp_client_socket2.send_to(boost::asio::buffer(msg_incomplete), target_service);
                            boost::system::error_code ec;
                            udp_client_socket2.shutdown(boost::asio::socket_base::shutdown_both, ec);
                            udp_client_socket2.close(ec);
                        } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                            if (someip_tp_test::number_of_fragments < 5) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                return;
                            }
                            // increase second last segment by 16 byte
                            increase_segment_back(fragments_request_to_master_[4], 16);
                        }
                        for (auto iter = fragments_request_to_master_.rbegin(); iter != fragments_request_to_master_.rend(); iter++) {
                            udp_client_socket.send_to(boost::asio::buffer(*(*iter)), target_service);
                        }
                    }
                }
                {
                    while (wait_for_all_response_fragments_received_) {
                        if (std::cv_status::timeout ==
                                all_fragments_received_cond_.wait_for(its_lock,
                                        std::chrono::seconds(20))) {
                            ADD_FAILURE() << "Didn't receive response to"
                                    " fragmented message within time: " << std::uint32_t(mode);
                            return;
                        } else {
                            EXPECT_EQ(someip_tp_test::number_of_fragments, fragments_request_to_master_.size());
                            // create complete message from request
                            if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                                if (mode == ASCENDING) {
                                    if (someip_tp_test::number_of_fragments < 2) {
                                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                        return;
                                    }
                                    // decrease second segment by 16 byte
                                    decrease_segment_back(fragments_request_to_master_[1], 16);
                                } else if (mode == DESCENDING) {
                                    if (someip_tp_test::number_of_fragments < 5) {
                                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                        return;
                                    }
                                    // decrease fourth segment by 16 byte
                                    decrease_segment_back(fragments_request_to_master_[4], 16);
                                }
                            } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                                // remove the additional inserted bytes which weren't accepted on
                                // test masterside as they were overlapping
                                if (mode == ASCENDING) {
                                    decrease_segment_front_back(fragments_request_to_master_[2], 16);
                                    decrease_segment_front(fragments_request_to_master_[4], 16);
                                } else {
                                    decrease_segment_front_back(fragments_request_to_master_[4], 16);
                                }
                            }
                            vsomeip::message_buffer_t its_request = create_full_message(fragments_request_to_master_);
                            if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP ||
                                test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                                EXPECT_EQ(VSOMEIP_FULL_HEADER_SIZE +
                                          someip_tp_test::number_of_fragments * (someip_tp_test::max_segment_size - 160),
                                          its_request.size());
                            } else {
                                EXPECT_EQ(VSOMEIP_FULL_HEADER_SIZE +
                                          someip_tp_test::number_of_fragments * someip_tp_test::max_segment_size,
                                          its_request.size());
                            }
                            if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP && mode == ASCENDING) {
                                // response contains the additional 16 bytes of 2nd fragment instead
                                // of beginning of the 3rd fragment
                                for (std::uint32_t i = 0; i < 16; i++) {
                                    its_request[VSOMEIP_PAYLOAD_POS + 2 * (someip_tp_test::max_segment_size - 160) + i] = 0xff;
                                }
                            }

                            // create complete message from response
                            vsomeip::message_buffer_t its_response = create_full_message(fragments_response_of_master_);
                            if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP ||
                                test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                                EXPECT_EQ(VSOMEIP_FULL_HEADER_SIZE +
                                          someip_tp_test::number_of_fragments * (someip_tp_test::max_segment_size - 160),
                                          its_response.size());
                            } else {
                                EXPECT_EQ(VSOMEIP_FULL_HEADER_SIZE +
                                          someip_tp_test::number_of_fragments * someip_tp_test::max_segment_size,
                                          its_response.size());
                            }
                            // change message type of response to request again
                            its_response[VSOMEIP_MESSAGE_TYPE_POS] = static_cast<vsomeip::byte_t>(vsomeip::message_type_e::MT_REQUEST);
                            // request and response should now be equal
                            EXPECT_EQ(its_response.size(), its_request.size());
                            EXPECT_EQ(its_response, its_request);
                            EXPECT_EQ(0, std::memcmp(static_cast<void*>(&its_response[0]),
                                                     static_cast<void*>(&its_request[0]),
                                                     its_response.size()));
                            fragments_response_of_master_.clear();
                        }
                    }
                    wait_for_all_response_fragments_received_ = true;
                }
                fragments_request_to_master_.clear();
            }

            while (wait_for_all_event_fragments_received_) {
                if (std::cv_status::timeout ==
                         all_fragments_received_cond_.wait_for(its_lock,
                                 std::chrono::seconds(20))) {
                     ADD_FAILURE() << "Didn't receive fragmented event from "
                             " master within time";
                 }
            }
            // check if received event is correct
            {
                EXPECT_EQ(someip_tp_test::number_of_fragments, fragments_event_from_master_.size());
                // create complete message from event
                vsomeip::message_buffer_t its_event = create_full_message(fragments_event_from_master_);
                vsomeip::session_t its_event_session = vsomeip::bithelper::read_uint16_be(&its_event[VSOMEIP_SESSION_POS_MIN]);

                std::vector<vsomeip::message_buffer_ptr_t> its_cmp_event_fragments;
                create_fragments(someip_tp_test::number_of_fragments,
                                 someip_tp_test::service.service_id,
                                 someip_tp_test::service.instance_id,
                                 someip_tp_test::service.event_id,
                                 vsomeip::message_type_e::MT_NOTIFICATION,
                                 0x0, its_event_session, &its_cmp_event_fragments,
                                 (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) ?
                                     vsomeip::tp::tp::tp_max_segment_length_ - 160 :
                                     vsomeip::tp::tp::tp_max_segment_length_);
                vsomeip::message_buffer_t its_cmp_event = create_full_message(its_cmp_event_fragments);
                EXPECT_EQ(its_cmp_event.size(), its_event.size());
                EXPECT_EQ(its_cmp_event, its_event);
                EXPECT_EQ(0, std::memcmp(static_cast<void*>(&its_cmp_event[0]),
                                         static_cast<void*>(&its_event[0]),
                                         its_cmp_event.size()));
            }
            its_lock.unlock();
            udp_client_receive_thread.join();
        } catch (const std::exception& _e) {
            ADD_FAILURE() << "catched exception: " << _e.what();
        }
    });

    std::mutex all_fragments_received_as_server_mutex_;
    std::unique_lock<std::mutex> all_fragments_received_as_server_lock(all_fragments_received_as_server_mutex_);
    std::condition_variable all_fragments_received_as_server_cond_;
    std::atomic<bool> wait_for_all_fragments_received_as_server_(true);
    std::atomic<std::uint16_t> remote_client_request_port(0);

    std::thread udp_server_send_thread([&]() {
        // wait until client subscribed
        if (std::future_status::timeout == remote_client_subscribed.get_future().wait_for(std::chrono::seconds(10))) {
            ADD_FAILURE() << "Client didn't subscribe within time";
            return;
        }

        // send fragmented event to the master
        boost::asio::ip::udp::socket::endpoint_type master_client(address_remote_, remote_client_subscription_port);
        for (const order_e mode : {order_e::ASCENDING, order_e::DESCENDING}) {
            create_fragments(someip_tp_test::number_of_fragments,
                    someip_tp_test::service_slave.service_id,
                    someip_tp_test::service_slave.instance_id,
                    someip_tp_test::service_slave.event_id,
                    vsomeip::message_type_e::MT_NOTIFICATION,
                    vsomeip::ANY_CLIENT, 0xffff,
                    &fragments_event_to_master_,
                    (test_mode_ == someip_tp_test::test_mode_e::OVERLAP ||
                            test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) ?
                            vsomeip::tp::tp::tp_max_segment_length_ - 160 :
                            vsomeip::tp::tp::tp_max_segment_length_);
            if (mode == order_e::ASCENDING) {
                if (test_mode_ == someip_tp_test::test_mode_e::MIXED) {
                    if (someip_tp_test::number_of_fragments != 6) {
                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                    } else {
                        auto its_indexes = {2, 3, 5, 1, 4, 0};
                        std::cout << __LINE__ << ": using following predefined sequence to send event to master: ";
                        for (auto i : its_indexes) { std::cout << i << ", "; }
                        std::cout << std::endl;
                        for (int i : its_indexes) {
                            udp_server_socket.send_to(boost::asio::buffer(*fragments_event_to_master_[i]), master_client);
                        }
                    }
                } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                    if (someip_tp_test::number_of_fragments != 6) {
                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                    } else {
                        auto its_indexes = {0,2,4,5,1,3};
                        std::cout << __LINE__ << ": using following predefined sequence to send event to master: ";
                        for (auto i : its_indexes) { std::cout << i << ", "; }
                        std::cout << std::endl;
                        // increase second segment by 16 byte at front and back
                        increase_segment_front_back(fragments_event_to_master_[1], 16);
                        increase_segment_front(fragments_event_to_master_[3], 16);

                        for (int i : its_indexes) {
                            udp_server_socket.send_to(boost::asio::buffer(*fragments_event_to_master_[i]), master_client);
                        }
                    }
                } else if (test_mode_ == someip_tp_test::test_mode_e::DUPLICATE) {
                    if (someip_tp_test::number_of_fragments < 2) {
                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                        return;
                    }
                    for (auto iter = fragments_event_to_master_.begin();
                            iter != fragments_event_to_master_.end(); iter++) {
                        udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                        // send insert 2nd fragment twice
                        if (iter == fragments_event_to_master_.begin() + 1) {
                            udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                            // send oversized fragment as well
                            increase_segment_back(*iter, 4);
                            udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                            decrease_segment_back(*iter, 4);
                        }
                    }
                } else {
                    if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
                        if (someip_tp_test::number_of_fragments < 3) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        }
                        // send an event fragment with a different session ID first
                        vsomeip::message_buffer_t msg_incomplete(*fragments_event_to_master_[2]);
                        msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0x44;
                        msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0x44;
                        udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                        // send a request with a different service ID as well to test cleanup
                        msg_incomplete[VSOMEIP_SERVICE_POS_MIN] = 0xdd;
                        msg_incomplete[VSOMEIP_SERVICE_POS_MAX] = 0xdd;
                        msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0xdd;
                        msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0xdd;
                        udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                    } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                        if (someip_tp_test::number_of_fragments < 2) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        }
                        // increase second segment by 16 byte
                        increase_segment_back(fragments_event_to_master_[1], 16);

                        // send one oversize message as well
                        std::vector<vsomeip::message_buffer_ptr_t> oversized_event;
                        create_fragments(someip_tp_test::number_of_fragments + 1,
                                someip_tp_test::service_slave.service_id,
                                someip_tp_test::service_slave.instance_id,
                                someip_tp_test::service_slave.event_id,
                                vsomeip::message_type_e::MT_NOTIFICATION,
                                vsomeip::ANY_CLIENT, 0xffff,
                                &oversized_event,
                                vsomeip::tp::tp::tp_max_segment_length_);
                        for (const auto& fragment : oversized_event) {
                            udp_server_socket.send_to(boost::asio::buffer(*fragment), master_client);
                        }
                    }
                    for (const auto& fragment : fragments_event_to_master_) {
                        udp_server_socket.send_to(boost::asio::buffer(*fragment), master_client);
                    }
                }
            } else if (mode == order_e::DESCENDING) {
                if (test_mode_ == someip_tp_test::test_mode_e::MIXED) {
                    std::vector<int> its_indexes = create_shuffled_seqeuence(someip_tp_test::number_of_fragments);
                    std::cout << __LINE__ << ": using following random sequence to send event to master: ";
                    for (auto i : its_indexes) { std::cout << i << ", "; }
                    std::cout << std::endl;
                    for ( int i : its_indexes) {
                        udp_server_socket.send_to(boost::asio::buffer(*fragments_event_to_master_[i]), master_client);
                    }
                } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                    if (someip_tp_test::number_of_fragments != 6) {
                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                    } else {
                        auto its_indexes = {5,3,2,1,0,4};
                        std::cout << __LINE__ << ": using following predefined sequence to send event to master: ";
                        for (auto i : its_indexes) { std::cout << i << ", "; }
                        std::cout << std::endl;
                        // increase second last segment by 16 byte at front and back
                        increase_segment_front_back(fragments_event_to_master_[4], 16);
                        // update length
                        *(reinterpret_cast<vsomeip::length_t*>(&((*fragments_event_to_master_[4])[VSOMEIP_LENGTH_POS_MIN]))) =
                                htonl(static_cast<vsomeip::length_t>(fragments_event_to_master_[4]->size() - VSOMEIP_SOMEIP_HEADER_SIZE));
                        for (int i : its_indexes) {
                            udp_server_socket.send_to(boost::asio::buffer(*fragments_event_to_master_[i]), master_client);
                        }
                    }
                } else if (test_mode_ == someip_tp_test::test_mode_e::DUPLICATE) {
                    if (someip_tp_test::number_of_fragments < 2) {
                        ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                        return;
                    }
                    for (auto iter = fragments_event_to_master_.rbegin();
                            iter != fragments_event_to_master_.rend(); iter++) {
                        udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                        // send insert 2nd last fragment twice
                        if (iter == fragments_event_to_master_.rbegin() + 1) {
                            udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                        }
                    }
                } else {
                    if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
                        if (someip_tp_test::number_of_fragments < 4) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        }
                        // send an event fragment with a different session ID first
                        vsomeip::message_buffer_t msg_incomplete(*fragments_event_to_master_[3]);
                        msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0x55;
                        msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0x55;
                        udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                        // send a request with a different service ID as well to test cleanup
                        msg_incomplete[VSOMEIP_SERVICE_POS_MIN] = 0xbb;
                        msg_incomplete[VSOMEIP_SERVICE_POS_MAX] = 0xbb;
                        msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0xbb;
                        msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0xbb;
                        udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);

                    } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                        if (someip_tp_test::number_of_fragments < 5) {
                            ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            return;
                        }
                        // increase second last segment by 16 byte
                        increase_segment_back(fragments_event_to_master_[4], 16);
                    }
                    for (auto iter = fragments_event_to_master_.rbegin(); iter != fragments_event_to_master_.rend(); iter++) {
                        udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                    }
                }
            }
            std::cout << __LINE__ << ": send event to master " << std::uint32_t(mode) << std::endl;
        }

        for (const order_e mode : {order_e::ASCENDING, order_e::DESCENDING}) {
            while (wait_for_all_fragments_received_as_server_) {
                if (std::cv_status::timeout ==
                        all_fragments_received_as_server_cond_.wait_for(all_fragments_received_as_server_lock,
                                std::chrono::seconds(20))) {
                    ADD_FAILURE() << "Didn't receive request from client within time: " << std::uint32_t(mode);
                    return;
                } else {
                    EXPECT_EQ(someip_tp_test::number_of_fragments, fragments_received_as_server_.size());
                    // create complete message from request of client
                    vsomeip::message_buffer_t its_request = create_full_message(fragments_received_as_server_);
                    if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP ||
                            test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                        EXPECT_EQ(VSOMEIP_FULL_HEADER_SIZE +
                                  someip_tp_test::number_of_fragments * (someip_tp_test::max_segment_size - 160),
                                  its_request.size());
                    } else {
                        EXPECT_EQ(VSOMEIP_FULL_HEADER_SIZE +
                                  someip_tp_test::number_of_fragments * someip_tp_test::max_segment_size,
                                  its_request.size());
                    }
                    const vsomeip::client_t its_request_client   = vsomeip::bithelper::read_uint16_be(&its_request[VSOMEIP_CLIENT_POS_MIN]);
                    const vsomeip::session_t its_request_session = vsomeip::bithelper::read_uint16_be(&its_request[VSOMEIP_SESSION_POS_MIN]);

                    create_fragments(someip_tp_test::number_of_fragments,
                                     someip_tp_test::service_slave.service_id,
                                     someip_tp_test::service_slave.instance_id,
                                     someip_tp_test::service_slave.method_id,
                                     vsomeip::message_type_e::MT_RESPONSE,
                                     its_request_client,
                                     its_request_session,
                                     &fragments_response_to_master_,
                                     (test_mode_ == someip_tp_test::test_mode_e::OVERLAP ||
                                             test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) ?
                                             vsomeip::tp::tp::tp_max_segment_length_ - 160:
                                             vsomeip::tp::tp::tp_max_segment_length_);
                    // create complete message from response
                    vsomeip::message_buffer_t its_response = create_full_message(fragments_response_to_master_);
                    // change the message type of the response to request for comparison
                    its_response[VSOMEIP_MESSAGE_TYPE_POS] = static_cast<vsomeip::byte_t>(vsomeip::message_type_e::MT_REQUEST);

                    EXPECT_EQ(its_response.size(), its_request.size());
                    EXPECT_EQ(its_response, its_request);
                    EXPECT_EQ(0, std::memcmp(static_cast<void*>(&its_response[0]),
                                             static_cast<void*>(&its_request[0]),
                                             its_response.size()));
                    // send back response
                    fragments_received_as_server_.clear();
                    EXPECT_GT(remote_client_request_port, 0);
                    boost::asio::ip::udp::socket::endpoint_type master_client(address_remote_, remote_client_request_port);
                    if (mode == order_e::ASCENDING) {
                        if (test_mode_ == someip_tp_test::test_mode_e::MIXED) {
                            if (someip_tp_test::number_of_fragments != 6) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            } else {
                                auto its_indexes = {4,2,0,1,3,5};
                                std::cout << __LINE__ << ": using following predefined sequence to send back response to master: ";
                                for (auto i : its_indexes) { std::cout << i << ", "; }
                                std::cout << std::endl;
                                for (int i : its_indexes) {
                                    udp_server_socket.send_to(boost::asio::buffer(*fragments_response_to_master_[i]), master_client);
                                }
                            }
                        } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                            if (someip_tp_test::number_of_fragments != 6) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            } else {
                                auto its_indexes = {0,2,4,3,5,1};
                                std::cout << __LINE__ << ": using following predefined sequence to send response to master: ";
                                for (auto i : its_indexes) { std::cout << i << ", "; }
                                std::cout << std::endl;
                                // increase fourth segment by 16 byte at front and back
                                increase_segment_front_back(fragments_response_to_master_[3], 16);
                                increase_segment_front(fragments_response_to_master_[1], 16);
                                for (int i : its_indexes) {
                                    udp_server_socket.send_to(boost::asio::buffer(*fragments_response_to_master_[i]), master_client);
                                }
                            }
                        } else if (test_mode_ == someip_tp_test::test_mode_e::DUPLICATE) {
                            if (someip_tp_test::number_of_fragments < 2) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                return;
                            }
                            for (auto iter = fragments_response_to_master_.begin();
                                    iter != fragments_response_to_master_.end(); iter++) {
                                udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                                // send 2nd fragment twice
                                if (iter == fragments_response_to_master_.begin() + 1) {
                                    udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                                    // send a fragment with invalid segment size as well
                                    decrease_segment_back(*iter, 16);
                                    increase_segment_back(*iter, 7);
                                    udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                                    increase_segment_back(*iter, 9);
                                }
                            }
                        } else {
                            if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
                                if (someip_tp_test::number_of_fragments < 5) {
                                    ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                    return;
                                }
                                // send an event fragment with a different session ID first
                                vsomeip::message_buffer_t msg_incomplete(*fragments_response_to_master_[4]);
                                msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0x99;
                                msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0x99;
                                udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                                // send a request with a different service ID as well to test cleanup
                                msg_incomplete[VSOMEIP_SERVICE_POS_MIN] = 0xaa;
                                msg_incomplete[VSOMEIP_SERVICE_POS_MAX] = 0xaa;
                                msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0xaa;
                                msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0xaa;
                                udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                            } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                                if (someip_tp_test::number_of_fragments < 2) {
                                    ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                    return;
                                }
                                // increase second segment by 16 byte
                                increase_segment_back(fragments_response_to_master_[1], 16);
                            }
                            for (const auto& frag : fragments_response_to_master_) {
                                udp_server_socket.send_to(boost::asio::buffer(*frag), master_client);
                            }
                        }
                    } else if (mode == order_e::DESCENDING) {
                        if (test_mode_ == someip_tp_test::test_mode_e::MIXED) {
                            std::vector<int> its_indexes = create_shuffled_seqeuence(someip_tp_test::number_of_fragments);
                            std::cout << __LINE__ << ": using following random sequence to send back response to master: ";
                            for (auto i : its_indexes) { std::cout << i << ", "; }
                            std::cout << std::endl;
                            for ( int i : its_indexes) {
                                udp_server_socket.send_to(boost::asio::buffer(*fragments_response_to_master_[i]), master_client);
                            }
                        } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP_FRONT_BACK) {
                            if (someip_tp_test::number_of_fragments != 6) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                            } else {
                                auto its_indexes = {5,3,2,1,4,0};
                                std::cout << __LINE__ << ": using following predefined sequence to send response to master: ";
                                for (auto i : its_indexes) { std::cout << i << ", "; }
                                std::cout << std::endl;
                                // increase fith segment by 16 byte at front and back
                                increase_segment_front_back(fragments_response_to_master_[4], 16);
                                for (int i : its_indexes) {
                                    udp_server_socket.send_to(boost::asio::buffer(*fragments_response_to_master_[i]), master_client);
                                }
                            }
                        } else if (test_mode_ == someip_tp_test::test_mode_e::DUPLICATE) {
                            if (someip_tp_test::number_of_fragments < 2) {
                                ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                return;
                            }
                            for (auto iter = fragments_response_to_master_.rbegin();
                                    iter != fragments_response_to_master_.rend(); iter++) {
                                udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                                // send insert 2nd last fragment twice
                                if (iter == fragments_response_to_master_.rbegin() + 1) {
                                    udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                                }
                            }
                        } else {
                            if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
                                if (someip_tp_test::number_of_fragments < 4) {
                                    ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                    return;
                                }
                                // send an event fragment with a different session ID first
                                vsomeip::message_buffer_t msg_incomplete(*fragments_response_to_master_[3]);
                                msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0x66;
                                msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0x66;
                                udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                                // send a request with a different service ID as well to test cleanup
                                msg_incomplete[VSOMEIP_SERVICE_POS_MIN] = 0xef;
                                msg_incomplete[VSOMEIP_SERVICE_POS_MAX] = 0xef;
                                msg_incomplete[VSOMEIP_SESSION_POS_MIN] = 0xef;
                                msg_incomplete[VSOMEIP_SESSION_POS_MAX] = 0xef;
                                udp_server_socket.send_to(boost::asio::buffer(msg_incomplete), master_client);
                            } else if (test_mode_ == someip_tp_test::test_mode_e::OVERLAP) {
                                if (someip_tp_test::number_of_fragments < 5) {
                                    ADD_FAILURE() << "line: " << __LINE__ << " needs adaption as number_of_fragments changed";
                                    return;
                                }
                                // increase second last segment by 16 byte
                                increase_segment_back(fragments_response_to_master_[4], 16);
                            }
                            for (auto iter = fragments_response_to_master_.rbegin();
                                      iter != fragments_response_to_master_.rend(); iter++) {
                                udp_server_socket.send_to(boost::asio::buffer(*(*iter)), master_client);
                            }
                        }
                    }
                }
            }
            wait_for_all_fragments_received_as_server_ = true;
        }
    });

    std::thread udp_server_receive_thread([&]() {
        {
            std::lock_guard<std::mutex> its_lock(udp_sd_socket_mutex);
            offer_service(&udp_sd_socket);
        }

        bool keep_receiving(true);
        std::vector<std::uint8_t> receive_buffer(4096);
        while (keep_receiving) {
            boost::system::error_code error;
            boost::asio::ip::udp::socket::endpoint_type its_remote_endpoint;
            std::size_t bytes_transferred = udp_server_socket.receive_from(
                    boost::asio::buffer(receive_buffer, receive_buffer.capacity()), its_remote_endpoint, 0, error);
            if (error) {
                keep_receiving = false;
                ADD_FAILURE() << __func__ << " error: " << error.message();
                return;
            } else {
                remote_client_request_port = its_remote_endpoint.port();
                std::uint32_t its_pos = 0;
                while (bytes_transferred > 0) {
                    const std::uint32_t its_message_size = vsomeip::bithelper::read_uint32_be(
                                                            &receive_buffer[its_pos + VSOMEIP_LENGTH_POS_MIN])
                                                            + VSOMEIP_SOMEIP_HEADER_SIZE;

                    std::cout << __LINE__ << ": received request from master " << its_message_size << std::endl;

                    vsomeip::deserializer its_deserializer(&receive_buffer[its_pos], its_message_size, 0);
                    vsomeip::service_t its_service = vsomeip::bithelper::read_uint16_be(&receive_buffer[its_pos + VSOMEIP_SERVICE_POS_MIN]);
                    vsomeip::method_t its_method   = vsomeip::bithelper::read_uint16_be(&receive_buffer[its_pos + VSOMEIP_METHOD_POS_MIN]);

                    EXPECT_EQ(someip_tp_test::service_slave.service_id, its_service);
                    EXPECT_EQ(someip_tp_test::service_slave.method_id, its_method);
                    vsomeip::message_impl msg;
                    EXPECT_TRUE(msg.deserialize(&its_deserializer));
                    if (vsomeip::tp::tp::tp_flag_is_set(receive_buffer[its_pos + VSOMEIP_MESSAGE_TYPE_POS])) {
                        auto its_buffer = std::make_shared<vsomeip::message_buffer_t>(&receive_buffer[its_pos], &receive_buffer[its_pos] + its_message_size);

                        fragments_received_as_server_.push_back(its_buffer);
                        if (fragments_received_as_server_.size() == someip_tp_test::number_of_fragments) {
                            std::lock_guard<std::mutex> its_lock(all_fragments_received_as_server_mutex_);
                            wait_for_all_fragments_received_as_server_ = false;
                            std::cout << __LINE__ << ": received all fragments as server" << std::endl;
                            all_fragments_received_as_server_cond_.notify_one();
                            static int received_requests = 0;
                            if (++received_requests == 2) {
                                std::cout << __LINE__ << ": received all requests as server --> Finished" << std::endl;
                                keep_receiving = false;
                            }
                        }
                    }
                    its_pos += its_message_size;
                    bytes_transferred -= its_message_size;
                }
            }
        }
    });

    send_thread.join();
    sd_receive_thread.join();
    udp_server_receive_thread.join();
    udp_server_send_thread.join();

    if (test_mode_ == someip_tp_test::test_mode_e::INCOMPLETE) {
        std::cout << "Sleeping to let cleanup for unfinished TP message "
                "trigger on master side..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(11));
    }
    // shutdown the server
    call_shutdown_method();

    boost::system::error_code ec;
    udp_sd_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
    udp_sd_socket.close(ec);
    udp_client_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
    udp_client_socket.close(ec);
    udp_server_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
    udp_server_socket.close(ec);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 3) {
        std::cerr << "Please pass an target, local IP address and test mode to this binary like: "
                << argv[0] << " 10.0.3.1 10.0.3.202 TP_IN_SEQUENCE" << std::endl;
        std::cerr << "Testmodes are [ IN_SEQUENCE, MIXED, INCOMPLETE, OVERLAP, OVERLAP_FRONT_BACK ]" << std::endl;
    } else {
        remote_address = argv[1];
        local_address = argv[2];
        std::string its_testmode = argv[3];
        if (its_testmode == std::string("IN_SEQUENCE")) {
            ::testing::GTEST_FLAG(filter) = "*send_in_mode/0";
        } else if (its_testmode == std::string("MIXED")) {
            ::testing::GTEST_FLAG(filter) = "*send_in_mode/1";
        } else if (its_testmode == std::string("INCOMPLETE")) {
            ::testing::GTEST_FLAG(filter) = "*send_in_mode/2";
        } else if (its_testmode == std::string("DUPLICATE")) {
            ::testing::GTEST_FLAG(filter) = "*send_in_mode/3";
        } else if (its_testmode == std::string("OVERLAP")) {
            ::testing::GTEST_FLAG(filter) = "*send_in_mode/4";
        } else if (its_testmode == std::string("OVERLAP_FRONT_BACK")) {
            ::testing::GTEST_FLAG(filter) = "*send_in_mode/5";
        }
    }
    return RUN_ALL_TESTS();
}
#endif
