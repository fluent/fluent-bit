// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#include <gtest/gtest.h>
#include <vsomeip/defines.hpp>

#include "../../../implementation/configuration/include/configuration_impl.hpp"
#include "../../../implementation/utility/include/bithelper.hpp"
#include "../../../implementation/utility/include/utility.hpp"

using vsomeip_v3::bithelper;

namespace {
    const std::uint8_t array_size = 18;
    const std::uint8_t array_size_too_short = 2;
    const std::uint32_t payload_length = 2;
    const vsomeip_v3::byte_t serviceID_byte1 = 0x01;
    const vsomeip_v3::byte_t serviceID_byte2 = 0x02;
    const vsomeip_v3::byte_t methodID_byte1 = 0x03;
    const vsomeip_v3::byte_t methodID_byte2 = 0x04;
    const vsomeip_v3::byte_t length_byte1 = 0x00;
    const vsomeip_v3::byte_t length_byte2 = 0x00;
    const vsomeip_v3::byte_t length_byte3 = 0x00;
    const vsomeip_v3::byte_t length_byte4 = 0x0A;
    const vsomeip_v3::byte_t clientID_byte1 = 0x00;
    const vsomeip_v3::byte_t clientID_byte2 = 0x00;
    const vsomeip_v3::byte_t sessionID_byte1 = 0x00;
    const vsomeip_v3::byte_t sessionID_byte2 = 0x00;
    const vsomeip_v3::byte_t version_byte = 0x01;
    const vsomeip_v3::byte_t interface_byte = 0x02;
    const vsomeip_v3::byte_t messageType_byte = 0x02;
    const vsomeip_v3::byte_t returnCode_byte = 0x00;
    const vsomeip_v3::byte_t payload_byte1 = 0x13;
    const vsomeip_v3::byte_t payload_byte2 = 0x37;
}

TEST(utility_test, get_message_size) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Create an array of size 18. 4 header, 4 size, 10 payload bytes.
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{
        serviceID_byte1, serviceID_byte2,
        methodID_byte1, methodID_byte2,
        length_byte1, length_byte2, length_byte3, length_byte4,
        clientID_byte1, clientID_byte2,
        sessionID_byte1, sessionID_byte2,
        version_byte,
        interface_byte,
        messageType_byte,
        returnCode_byte,
        payload_byte1, payload_byte2
    };

    // Create an array to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_array_{length_byte1, length_byte2, length_byte3, length_byte4};

    // Getting size.
    std::uint32_t size_ = VSOMEIP_SOMEIP_HEADER_SIZE + bithelper::read_uint32_be(uint32_array_.data());

    // Check if function returns the uint32_t size_ we expect to receive, header + size passed by the 4 length_bytes.
    ASSERT_EQ(its_utility->get_message_size(byte_array_.data(), byte_array_.size()), size_);

    // Make the 4 size bytes equal to zero.
    byte_array_.at(4) = 0;
    byte_array_.at(5) = 0;
    byte_array_.at(6) = 0;
    byte_array_.at(7) = 0;
    // Check that the message size is now equal to only the someip header.
    ASSERT_EQ(its_utility->get_message_size(byte_array_.data(), byte_array_.size()), VSOMEIP_SOMEIP_HEADER_SIZE);

    // Create an array shorter than the minimum someip header.
    std::array<vsomeip_v3::byte_t, array_size_too_short> byte_array_too_short{serviceID_byte1, serviceID_byte2};
    // Check that 0 is returned for the expected length of the message.
    ASSERT_EQ(its_utility->get_message_size(byte_array_too_short.data(), byte_array_too_short.size()), 0);
}

TEST(utility_test, get_payload_size) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Anatomy of a SOMEIP message.
    // Byte 1-2: Service ID, Byte 3-4: Method ID, Byte 5-8: length,
    // byte 9-10: Client id, byte 11-12: session id,
    // byte 13: SOME/IP version, byte 14: interface version,
    // byte 15: Message type, byte 16: Return Code.
    // Length are all the bytes that come after it. (byte 9+)
    // Payload here is the bytes that come after all those (byte 16++).

    // Create an array of size 18. 4 header, 4 size, 10 payload bytes.
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{
        serviceID_byte1, serviceID_byte2,
        methodID_byte1, methodID_byte2,
        length_byte1, length_byte2, length_byte3, length_byte4,
        clientID_byte1, clientID_byte2,
        sessionID_byte1, sessionID_byte2,
        version_byte,
        interface_byte,
        messageType_byte,
        returnCode_byte,
        payload_byte1, payload_byte2
    };

    // Check if function returns the uint32_t size_ we expect to receive, header + size passed by the 4 length_bytes.
    ASSERT_EQ(its_utility->get_payload_size(byte_array_.data(), byte_array_.size()), payload_length);

    // Check if function returns 0, if length field we pass (0x0A) passed is greater than the array size - 8
    ASSERT_EQ(its_utility->get_payload_size(byte_array_.data(), byte_array_.size() - VSOMEIP_SOMEIP_HEADER_SIZE), 0);

    // Make the length smaller than 8.
    byte_array_.at(4) = 0;
    byte_array_.at(5) = 0;
    byte_array_.at(6) = 0;
    byte_array_.at(7) = 7;
    // Check that the message size is now equal to only the someip header.
    ASSERT_EQ(its_utility->get_payload_size(byte_array_.data(), byte_array_.size()), 0);

    // Create an array shorter than the minimum someip header.
    std::array<vsomeip_v3::byte_t, array_size_too_short> byte_array_too_short{serviceID_byte1, serviceID_byte2};
    // Check that 0 is returned for the expected length of the message.
    ASSERT_EQ(its_utility->get_payload_size(byte_array_too_short.data(), byte_array_too_short.size()), 0);
}

TEST(utility_test, is_routing_manager) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Random network name.
    const std::string network_("test_network");

    // First caller become the routing manager.
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Subsequent callers can not be routing manager.
    ASSERT_FALSE(its_utility->is_routing_manager(network_));

    // Clean up.
    its_utility->remove_lockfile(network_);

    std::unique_ptr<vsomeip_v3::utility> its_utility2;

    // Weird network name.
    const std::string network2_("\\\\////\0");

    // Expect the network name to lead to failure.
    ASSERT_FALSE(its_utility2->is_routing_manager(network2_));
}

TEST(utility_test, remove_lockfile) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Random network name.
    const std::string network_("test");

    // Expect nothing to happen.
    its_utility->remove_lockfile(network_);

    // First caller become the routing manager.
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Subsequent callers can not be routing manager.
    ASSERT_FALSE(its_utility->is_routing_manager(network_));

    its_utility->remove_lockfile(network_);

    // Since the network got erased this shoud return true once more, as new "first caller".
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Clean up.
    its_utility->remove_lockfile(network_);

    // WIP not sure how to rest failure to close or remove the test.lck file.
}

TEST(utility_test, exists) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Random network name.
    const std::string network_("exists_tests");

    // Expect false.
    ASSERT_FALSE(its_utility->exists(network_));

    // First caller become the routing manager, creating the network creates file /tmp/exists_tests.lck
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Create a path variable.
    const std::string path_("/tmp/exists_tests.lck");

    // Expect true.
    ASSERT_TRUE(its_utility->exists(path_));

    // Clean up.
    its_utility->remove_lockfile(network_);

    // Expect false since file should be erased.
    ASSERT_FALSE(its_utility->exists(path_));
}

TEST(utility_test, is_file) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Random network name.
    const std::string network_("is_file_tests");
    const std::string file_("/tmp/is_file_tests.lck");
    const std::string directory_("/tmp/");

    // Expect false.
    ASSERT_FALSE(its_utility->is_file(network_));

    // Expect false since file is not yet created.
    ASSERT_FALSE(its_utility->is_file(file_));

    // Expect false since we pass a directory.
    ASSERT_FALSE(its_utility->is_file(directory_));

    // First caller become the routing manager, creating the network creates file /tmp/is_file_tests.lck
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Expect true.
    ASSERT_TRUE(its_utility->is_file(file_));

    // Clean up
    its_utility->remove_lockfile(network_);
}

TEST(utility_test, is_folder) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Random network name.
    const std::string network_("is_folder_tests");
    const std::string file_("/tmp/is_folder_tests.lck");
    const std::string directory_("/tmp/");

    // Expect false.
    ASSERT_FALSE(its_utility->is_folder(network_));

    // Expect false since file is not a folder.
    ASSERT_FALSE(its_utility->is_folder(file_));

    // First caller become the routing manager, creating the network creates file /tmp/is_folder_tests.lck
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Expect true.
    ASSERT_TRUE(its_utility->is_folder(directory_));

    // Clean up
    its_utility->remove_lockfile(network_);
}

TEST(utility_test, get_base_path) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    // Random network name.
    const std::string network_("is_folder_tests");
    const std::string base_path_("/tmp/is_folder_tests-");

    // First caller become the routing manager, creating the network creates file /tmp/is_folder_tests.lck
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Assert equal
    ASSERT_EQ(its_utility->get_base_path(network_), base_path_);

    // Clean up
    its_utility->remove_lockfile(network_);
}

TEST(utility_test, request_client_id) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    const std::string path_("/tmp/");
    std::shared_ptr<vsomeip_v3::cfg::configuration_impl> its_config =
        std::make_shared<vsomeip_v3::cfg::configuration_impl>(path_);

    // Client info
    vsomeip_v3::client_t client_ = 0x1000;
    const std::string client_name_("client");
    vsomeip_v3::client_t client2_ = VSOMEIP_CLIENT_UNSET;
    const std::string client_name2_("client2");

    // Default network name of config
    const std::string network_("vsomeip");

    // Network should not exist yet, expect client to be unset.
    ASSERT_EQ(its_utility->request_client_id(its_config, client_name_, client_), VSOMEIP_CLIENT_UNSET);

    // Call is_routing_manager to create the network
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Test method expect to return the client_ id.
    ASSERT_EQ(its_utility->request_client_id(its_config, client_name_, client_), client_);

    // Get from the configs the smallest and biggest client numbers that can be assigned.
    // Should be 0x100 to 0x1ff
    static const std::uint16_t its_diagnosis_mask = its_config->get_diagnosis_mask();
    static const std::uint16_t its_masked_diagnosis_address = static_cast<std::uint16_t>(
            (its_config->get_diagnosis_address() << 8) & its_diagnosis_mask);
    static const std::uint16_t its_client_mask = static_cast<std::uint16_t>(~its_diagnosis_mask);
    static const std::uint16_t  its_biggest_client = its_masked_diagnosis_address | its_client_mask;
    static const std::uint16_t  its_smallest_client = its_masked_diagnosis_address;

    std::uint16_t client_id = its_utility->request_client_id(its_config, client_name2_, client2_);

    // Expect first call with unset id to be the smallest client allowed +1.
    ASSERT_EQ(client_id, its_smallest_client+1);

    // Cycle through all numbers available.
    while(client_id < its_biggest_client)
    {
        client_id = its_utility->request_client_id(its_config, client_name2_, client2_);
        ASSERT_GE(client_id, its_smallest_client);
        ASSERT_LE(client_id, its_biggest_client);
    }

    // Expect the client id to be the biggest client client number allowed.
    ASSERT_EQ(client_id, its_biggest_client);

    // Expect unset since all numbers have been used.
    ASSERT_EQ(its_utility->request_client_id(its_config, client_name2_, client2_), VSOMEIP_CLIENT_UNSET);

    // Clean up
    its_utility->remove_lockfile(network_);
}

TEST(utility_test, get_used_client_ids) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    const std::string path_("/tmp/");
    std::shared_ptr<vsomeip_v3::cfg::configuration_impl> its_config =
        std::make_shared<vsomeip_v3::cfg::configuration_impl>(path_);

    // Client info
    vsomeip_v3::client_t client_ = 0x1000;
    vsomeip_v3::client_t client1_ = 0x1001;
    vsomeip_v3::client_t client2_ = 0x1002;
    vsomeip_v3::client_t client3_ = 0x1003;
    vsomeip_v3::client_t client4_ = 0x1004;
    const std::string client_name_("client");

    // Default network name of config
    const std::string network_("vsomeip");

    // Call is_routing_manager to create the network
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Call request client id to emplace a client.
    ASSERT_EQ(its_utility->request_client_id(its_config, client_name_, client_), client_);

    // Test method expect to return the client_ id.
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 1);

    its_utility->request_client_id(its_config, client_name_, client1_);
    its_utility->request_client_id(its_config, client_name_, client2_);
    its_utility->request_client_id(its_config, client_name_, client3_);
    its_utility->request_client_id(its_config, client_name_, client4_);

    // Test method expect to return the client_ id.
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 5);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).count(VSOMEIP_CLIENT_UNSET), 0);

    // Clean up
    its_utility->remove_lockfile(network_);
}

TEST(utility_test, release_client_id) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    const std::string path_("/tmp/");
    std::shared_ptr<vsomeip_v3::cfg::configuration_impl> its_config =
        std::make_shared<vsomeip_v3::cfg::configuration_impl>(path_);

    // Client info
    vsomeip_v3::client_t client_ = 0x1000;
    vsomeip_v3::client_t client1_ = 0x1001;
    vsomeip_v3::client_t client2_ = 0x1002;
    vsomeip_v3::client_t client3_ = 0x1003;
    vsomeip_v3::client_t client4_ = 0x1004;
    const std::string client_name_("client");

    // Default network name of config
    const std::string network_("vsomeip");

    // Call is_routing_manager to create the network
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Call request client id to emplace a clients.
    its_utility->request_client_id(its_config, client_name_, client_);
    its_utility->request_client_id(its_config, client_name_, client1_);
    its_utility->request_client_id(its_config, client_name_, client2_);
    its_utility->request_client_id(its_config, client_name_, client3_);
    its_utility->request_client_id(its_config, client_name_, client4_);

    // Expect to get size 5
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 5);

    // Test Method.
    its_utility->release_client_id(network_, client_);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 4);

    its_utility->release_client_id(network_, client1_);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 3);

    its_utility->release_client_id(network_, client2_);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 2);

    its_utility->release_client_id(network_, client3_);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 1);

    its_utility->release_client_id(network_, client4_);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 0);

    // Clean up
    its_utility->remove_lockfile(network_);
}

TEST(utility_test, reset_client_ids) {
    std::unique_ptr<vsomeip_v3::utility> its_utility;

    const std::string path_("/tmp/");
    std::shared_ptr<vsomeip_v3::cfg::configuration_impl> its_config =
        std::make_shared<vsomeip_v3::cfg::configuration_impl>(path_);

    // Client info
    vsomeip_v3::client_t client_ = 0x1000;
    vsomeip_v3::client_t client1_ = 0x1001;
    vsomeip_v3::client_t client2_ = 0x1002;
    vsomeip_v3::client_t client3_ = 0x1003;
    vsomeip_v3::client_t client4_ = 0x1004;
    const std::string client_name_("client");

    // Default network name of config
    const std::string network_("vsomeip");

    // Call is_routing_manager to create the network
    ASSERT_TRUE(its_utility->is_routing_manager(network_));

    // Call request client id to emplace a clients.
    its_utility->request_client_id(its_config, client_name_, client_);
    its_utility->request_client_id(its_config, client_name_, client1_);
    its_utility->request_client_id(its_config, client_name_, client2_);
    its_utility->request_client_id(its_config, client_name_, client3_);
    its_utility->request_client_id(its_config, client_name_, client4_);

    // Expect to get size 5
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 5);

    // Test Method.
    its_utility->reset_client_ids(network_);
    ASSERT_EQ(its_utility->get_used_client_ids(network_).size(), 0);

    // Clean up
    its_utility->remove_lockfile(network_);
}
