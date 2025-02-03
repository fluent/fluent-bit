// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <exception>
#include <iostream>

#include <gtest/gtest.h>

#include <boost/asio.hpp>

static char* passed_address;

TEST(someip_offer_test, send_offer_service_sd_message)
{
    try {
        boost::asio::io_context io;
        boost::asio::ip::udp::socket::endpoint_type target_sd(
                boost::asio::ip::address::from_string(std::string(passed_address)),
                30490);
        boost::asio::ip::udp::socket udp_socket(io,
                boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 30490));
        std::uint8_t its_offer_service_message[] = {
            0xff, 0xff, 0x81, 0x00,
            0x00, 0x00, 0x00, 0x3c,
            0x00, 0x00, 0x00, 0x01,
            0x01, 0x01, 0x02, 0x00,
            0xc0, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
            0x01, 0x00, 0x00, 0x20,
            0x11, 0x11, 0x00, 0x01,
            0x00, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x18,
            0x00, 0x09, 0x04, 0x00,
            0x0a, 0x00, 0x03, 0x01,
            0x00, 0x06, 0x9c, 0x41,
            0x00, 0x09, 0x04, 0x00,
            0x0a, 0x00, 0x03, 0x7D, // slave address
            0x00, 0x11, 0x75, 0x31
        };
        for (int var = 0; var < 15; ++var) {
            udp_socket.send_to(boost::asio::buffer(its_offer_service_message), target_sd);
            ++its_offer_service_message[11];
        }

        // call shutdown method
        std::uint8_t shutdown_call[] = {
            0x11, 0x11, 0x14, 0x04,
            0x00, 0x00, 0x00, 0x08,
            0x22, 0x22, 0x00, 0x01,
            0x01, 0x00, 0x01, 0x00 };
        boost::asio::ip::udp::socket::endpoint_type target_service(
                boost::asio::ip::address::from_string(std::string(passed_address)),
                30001);
        udp_socket.send_to(boost::asio::buffer(shutdown_call), target_service);
    } catch (const std::exception& e) {
        std::cerr << "Caught exception: " << e.what() << '\n';
        ASSERT_FALSE(true);
    }
}


#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if(argc < 2) {
        std::cout << "Please pass an target IP address to this binary like: "
                << argv[0] << " 10.0.3.1" << std::endl;
        exit(1);
    }
    passed_address = argv[1];
    return RUN_ALL_TESTS();
}
#endif
