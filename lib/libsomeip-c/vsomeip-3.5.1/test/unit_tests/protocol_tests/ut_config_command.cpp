// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include "../../../implementation/protocol/include/config_command.hpp"
#include "../../../implementation/protocol/include/protocol.hpp"

namespace config_command_tests {

// Tester Note: Expect Little-Endian representation for serialized data.
const std::vector<std::uint8_t> serialized_config_command = {
        0x31, // config_command
        0x00, 0x00, // Version.
        0x01, 0x00, // Client.
        0x20, 0x00, 0x00, 0x00, // Size.
        // Configurations.
        0x04, 0x00, 0x00, 0x00, // Key size.
        0x61, 0x62, 0x63, 0x64, // "abcd"
        0x04, 0x00, 0x00, 0x00, // Value size.
        0x31, 0x32, 0x33, 0x34, // "1234"
        0x04, 0x00, 0x00, 0x00, // Key size.
        0x65, 0x66, 0x67, 0x68, // "efgh"
        0x04, 0x00, 0x00, 0x00, // Value size.
        0x35, 0x36, 0x37, 0x38 // "5678"
};

TEST(config_command_test, accessors) {
    vsomeip_v3::protocol::config_command command;
    ASSERT_FALSE(command.contains("abcd"));
    command.insert("abcd", "1234");
    ASSERT_TRUE(command.contains("abcd"));
    ASSERT_EQ(command.at("abcd"), "1234");
}

TEST(config_command_test, serialize) {
    vsomeip_v3::protocol::config_command command;
    command.set_client(0x0001);
    command.insert("abcd", "1234");
    command.insert("efgh", "5678");

    std::vector<std::uint8_t> buffer;
    vsomeip_v3::protocol::error_e error;
    command.serialize(buffer, error);
    ASSERT_EQ(error, vsomeip_v3::protocol::error_e::ERROR_OK);
    ASSERT_EQ(buffer, serialized_config_command);
}

TEST(config_command_test, deserialize) {
    vsomeip_v3::protocol::config_command command;
    vsomeip_v3::protocol::error_e error;
    command.deserialize(serialized_config_command, error);
    ASSERT_EQ(error, vsomeip_v3::protocol::error_e::ERROR_OK);
    ASSERT_EQ(command.configs().size(), 2);
    EXPECT_EQ(command.configs().at("abcd"), "1234");
    EXPECT_EQ(command.configs().at("efgh"), "5678");
}

} // namespace config_command_tests
