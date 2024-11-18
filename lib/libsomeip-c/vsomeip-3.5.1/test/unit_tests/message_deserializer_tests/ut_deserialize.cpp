// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <vsomeip/primitive_types.hpp>

#include "../../../implementation/message/include/deserializer.hpp"
#include "../../../implementation/utility/include/bithelper.hpp"

namespace {
    constexpr std::uint32_t buffer_shrink_threshold = 1;
    constexpr std::uint8_t array_size = 4;
    const vsomeip_v3::byte_t byte1 = 1;
    const vsomeip_v3::byte_t byte2 = 2;
    const vsomeip_v3::byte_t byte3 = 3;
    const vsomeip_v3::byte_t byte4 = 4;
    const bool omit_last_byte = true;
    const bool dont_omit_last_byte = false;
}

TEST(deserialize_test, deserialize_get_available) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Testing the correct array size is returned.
    ASSERT_EQ(its_deserializer->get_available(), array_size);
    ASSERT_EQ(its_deserializer->get_available(), its_deserializer->get_remaining());
}

TEST(deserialize_test, deserialize_set_get_remaining) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Testing the correct remaining length is returned after every step.
    vsomeip_v3::byte_t deserialized_byte_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(its_deserializer->get_remaining(), 3);
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(its_deserializer->get_remaining(), 2);
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(its_deserializer->get_remaining(), 1);
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(its_deserializer->get_remaining(), 0);

    // Setting the remaining size to array size to test setter.
    its_deserializer->set_remaining(array_size);
    ASSERT_EQ(its_deserializer->get_remaining(), array_size);
    ASSERT_NE(its_deserializer->get_remaining(), 0);
}

TEST(deserialize_test, deserialize_from_uint8) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Deserialize data 1 byte (uint8_t) at a time and check against expected value.
    vsomeip_v3::byte_t deserialized_byte_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte1);
    ASSERT_NE(deserialized_byte_, byte4);

    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte2);
    ASSERT_NE(deserialized_byte_, byte3);

    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte3);
    ASSERT_NE(deserialized_byte_, byte2);

    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte4);
    ASSERT_NE(deserialized_byte_, byte1);
}

TEST(deserialize_test, deserialize_from_uint16) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    // Create arrays to use with bithelper.
    std::array<vsomeip_v3::byte_t, 2> uint16_array_1_{byte1, byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_2_{byte3, byte4};

    // Creating two uint16_t with the data from the byte_array.
    std::uint16_t uint16_1 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_1_.data());
    std::uint16_t uint16_2 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_2_.data());

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Deserialize 2 uint16_t from the data, and compare them with their expected values.
    std::uint16_t deserialized_uint16_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_uint16_));
    ASSERT_EQ(deserialized_uint16_, uint16_1);
    ASSERT_NE(deserialized_uint16_, uint16_2);

    ASSERT_TRUE(its_deserializer->deserialize(deserialized_uint16_));
    ASSERT_EQ(deserialized_uint16_, uint16_2);
    ASSERT_NE(deserialized_uint16_, uint16_1);
}

TEST(deserialize_test, deserialize_from_uint32_omit_last_byte) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    // Create arrays to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_3_bytes_array_{0, byte1, byte2, byte3};
    std::array<vsomeip_v3::byte_t, 4> uint32_full_array_{byte1, byte2, byte3, byte4};

    // Create two uint32_t from the data, one including 3 bytes and the other with the full 4 bytes
    const std::uint32_t uint32_3_bytes = vsomeip_v3::bithelper::read_uint32_be(uint32_3_bytes_array_.data());
    const std::uint32_t uint32_full = vsomeip_v3::bithelper::read_uint32_be(uint32_full_array_.data());

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Deserialize a uint32_t omitting the last byte
    std::uint32_t deserialized_uint32_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_uint32_, omit_last_byte));
    ASSERT_EQ(deserialized_uint32_, uint32_3_bytes);
    ASSERT_NE(deserialized_uint32_, uint32_full);
}

TEST(deserialize_test, deserialize_from_uint32_dont_omit_last_byte) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    // Create arrays to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_3_bytes_array_{0, byte1, byte2, byte3};
    std::array<vsomeip_v3::byte_t, 4> uint32_full_array_{byte1, byte2, byte3, byte4};

    // Create two uint32_t from the data, one including 3 bytes and the other with the full 4 bytes
    const std::uint32_t uint32_3_bytes = vsomeip_v3::bithelper::read_uint32_be(uint32_3_bytes_array_.data());
    const std::uint32_t uint32_full = vsomeip_v3::bithelper::read_uint32_be(uint32_full_array_.data());

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Deserialize a full uint32_t not omitting the last byte.
    std::uint32_t deserialized_uint32_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_uint32_, dont_omit_last_byte));
    ASSERT_EQ(deserialized_uint32_, uint32_full);
    ASSERT_NE(deserialized_uint32_, uint32_3_bytes);
}

TEST(deserialize_test, deserialize_from_uint8_array_pointer_and_length) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // One shot deserialization of the full data.
    std::array<vsomeip_v3::byte_t, array_size> deserialized_byte_array_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_array_.data(), deserialized_byte_array_.size()));

    // Check deserialized data for endianness and expected values.
    ASSERT_EQ(deserialized_byte_array_.at(0), byte1);
    ASSERT_EQ(deserialized_byte_array_.at(1), byte2);
    ASSERT_EQ(deserialized_byte_array_.at(2), byte3);
    ASSERT_EQ(deserialized_byte_array_.at(3), byte4);
    ASSERT_NE(deserialized_byte_array_.at(0), byte4);
    ASSERT_NE(deserialized_byte_array_.at(1), byte3);
    ASSERT_NE(deserialized_byte_array_.at(2), byte2);
    ASSERT_NE(deserialized_byte_array_.at(3), byte1);

    // Attempt a second try with a step by step deserialization.
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer2(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Check deserialized data for endianness and expected values.
    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_byte_array_.data(), 2));
    ASSERT_EQ(deserialized_byte_array_.at(0), byte1);
    ASSERT_EQ(deserialized_byte_array_.at(1), byte2);
    ASSERT_NE(deserialized_byte_array_.at(0), byte2);
    ASSERT_NE(deserialized_byte_array_.at(1), byte1);

    // Check deserialized data against expected and old values.
    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_byte_array_.data(), 2));
    ASSERT_EQ(deserialized_byte_array_.at(0), byte3);
    ASSERT_EQ(deserialized_byte_array_.at(1), byte4);
    ASSERT_NE(deserialized_byte_array_.at(0), byte1);
    ASSERT_NE(deserialized_byte_array_.at(1), byte2);
}

TEST(deserialize_test, deserialize_from_string_pointer_and_length) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // One shot deserialization of the full data.
    std::string deserialized_string_ = "0000";
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_string_, array_size));

    // Check deserialized data for endianness and expected values.
    ASSERT_EQ(deserialized_string_[0], byte1);
    ASSERT_EQ(deserialized_string_[1], byte2);
    ASSERT_EQ(deserialized_string_[2], byte3);
    ASSERT_EQ(deserialized_string_[3], byte4);
    ASSERT_NE(deserialized_string_[0], byte4);
    ASSERT_NE(deserialized_string_[1], byte3);
    ASSERT_NE(deserialized_string_[2], byte2);
    ASSERT_NE(deserialized_string_[3], byte1);

    // Attempt a second try with a step by step deserialization.
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer2(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_string_, 2));

    // Check deserialized data for endianness and expected values.
    ASSERT_EQ(deserialized_string_[0], byte1);
    ASSERT_EQ(deserialized_string_[1], byte2);
    ASSERT_NE(deserialized_string_[0], byte2);
    ASSERT_NE(deserialized_string_[1], byte1);

    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_string_, 2));

    // Check deserialized data against expected and old values.
    ASSERT_EQ(deserialized_string_[0], byte3);
    ASSERT_EQ(deserialized_string_[1], byte4);
    ASSERT_NE(deserialized_string_[0], byte1);
    ASSERT_NE(deserialized_string_[1], byte2);

}

TEST(deserialize_test, deserialize_from_uint8_t_vector) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // One shot deserialization of the full data. Creating a vector with size 4
    std::vector<std::uint8_t> deserialized_vector_(4);

    ASSERT_TRUE(its_deserializer->deserialize(deserialized_vector_));

    // Check deserialized data for endianness and expected values.
    ASSERT_EQ(deserialized_vector_.at(0), byte1);
    ASSERT_EQ(deserialized_vector_.at(1), byte2);
    ASSERT_EQ(deserialized_vector_.at(2), byte3);
    ASSERT_EQ(deserialized_vector_.at(3), byte4);
    ASSERT_NE(deserialized_vector_.at(0), byte4);
    ASSERT_NE(deserialized_vector_.at(1), byte3);
    ASSERT_NE(deserialized_vector_.at(2), byte2);
    ASSERT_NE(deserialized_vector_.at(3), byte1);

    // Attempt a second try with a step by step deserialization.
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer2(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Creating a size 2 vector
    std::vector<std::uint8_t> deserialized_vector2_(2);

    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_vector2_));

    // Check deserialized data for endianness and expected values.
    ASSERT_EQ(deserialized_vector2_.at(0), byte1);
    ASSERT_EQ(deserialized_vector2_.at(1), byte2);
    ASSERT_NE(deserialized_vector2_.at(0), byte2);
    ASSERT_NE(deserialized_vector2_.at(1), byte1);

    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_vector2_));

    // Check deserialized data against expected and old values.
    ASSERT_EQ(deserialized_vector2_.at(0), byte3);
    ASSERT_EQ(deserialized_vector2_.at(1), byte4);
    ASSERT_NE(deserialized_vector2_.at(0), byte1);
    ASSERT_NE(deserialized_vector2_.at(1), byte2);
}

TEST(deserialize_test, look_ahead_for_uint8) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // look_ahead data 1 byte (uint8_t) at a time and check against expected value.
    vsomeip_v3::byte_t look_ahead_byte_;
    ASSERT_TRUE(its_deserializer->look_ahead(0, look_ahead_byte_));
    ASSERT_EQ(look_ahead_byte_, byte1);
    ASSERT_NE(look_ahead_byte_, byte4);

    ASSERT_TRUE(its_deserializer->look_ahead(1, look_ahead_byte_));
    ASSERT_EQ(look_ahead_byte_, byte2);
    ASSERT_NE(look_ahead_byte_, byte3);

    ASSERT_TRUE(its_deserializer->look_ahead(2, look_ahead_byte_));
    ASSERT_EQ(look_ahead_byte_, byte3);
    ASSERT_NE(look_ahead_byte_, byte2);

    ASSERT_TRUE(its_deserializer->look_ahead(3, look_ahead_byte_));
    ASSERT_EQ(look_ahead_byte_, byte4);
    ASSERT_NE(look_ahead_byte_, byte1);
}

TEST(deserialize_test, look_ahead_for_uint16) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    // Creating the three possible uint16_t with the data from the byte_array

    // Create arrays to use with bithelper.
    std::array<vsomeip_v3::byte_t, 2> uint16_array_1_{byte1, byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_2_{byte2, byte3};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_3_{byte3, byte4};

    // Creating two uint16_t with the data from the byte_array.
    std::uint16_t uint16_1 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_1_.data());
    std::uint16_t uint16_2 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_2_.data());
    std::uint16_t uint16_3 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_3_.data());

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Look_ahead uint16_t from incrementing indices and compare them with their expected values.
    std::uint16_t look_ahead_uint16_;
    ASSERT_TRUE(its_deserializer->look_ahead(0, look_ahead_uint16_));
    ASSERT_EQ(look_ahead_uint16_, uint16_1);
    ASSERT_NE(look_ahead_uint16_, uint16_2);

    ASSERT_TRUE(its_deserializer->look_ahead(1, look_ahead_uint16_));
    ASSERT_EQ(look_ahead_uint16_, uint16_2);
    ASSERT_NE(look_ahead_uint16_, uint16_1);

    ASSERT_TRUE(its_deserializer->look_ahead(2, look_ahead_uint16_));
    ASSERT_EQ(look_ahead_uint16_, uint16_3);
    ASSERT_NE(look_ahead_uint16_, uint16_1);
}

TEST(deserialize_test, look_ahead_for_uint32) {
    // Extend array size
    std::array<vsomeip_v3::byte_t, array_size+1> byte_array_{byte1, byte2, byte3, byte4, byte1};

    // Create arrays to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_1_bytes_array_{byte1, byte2, byte3, byte4};
    std::array<vsomeip_v3::byte_t, 4> uint32_2_bytes_array_{byte2, byte3, byte4, byte1};

    // Creating the uint32_t with the data from the byte_array
    const std::uint32_t uint32_1 = vsomeip_v3::bithelper::read_uint32_be(uint32_1_bytes_array_.data());
    const std::uint32_t uint32_2 = vsomeip_v3::bithelper::read_uint32_be(uint32_2_bytes_array_.data());

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Look_ahead uint32_t from incrementing indices and compare them with their expected values.
    std::uint32_t look_ahead_uint32_;
    ASSERT_TRUE(its_deserializer->look_ahead(0, look_ahead_uint32_));
    ASSERT_EQ(look_ahead_uint32_, uint32_1);
    ASSERT_NE(look_ahead_uint32_, uint32_2);

    ASSERT_TRUE(its_deserializer->look_ahead(1, look_ahead_uint32_));
    ASSERT_EQ(look_ahead_uint32_, uint32_2);
    ASSERT_NE(look_ahead_uint32_, uint32_1);
}

TEST(deserialize_test, deserialize_message) {
    // Extend array size to the size of a message without options
    // the 8 is the length of the header needs to be atleast 8 to offset the header length
    // the last bytes are all 0 to reflect uint32_t length
    std::array<vsomeip_v3::byte_t, 25> byte_array_{
                                        byte1, byte2, byte3, byte4, 0,
                                        0, 0, 8, byte4, byte1,
                                        byte1, byte2, byte3, byte4, byte1,
                                        byte1, byte2, byte3, byte4, byte1,
                                        0, 0, 0, 0, 0};

    // Deserialize expected to pass.
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    auto deserialized_message = its_deserializer->deserialize_message();
    ASSERT_NE(deserialized_message, nullptr);

    std::array<vsomeip_v3::byte_t, array_size> byte_array2_{byte1, byte2, byte3, byte4};
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer2(
        new vsomeip_v3::deserializer(byte_array2_.data(), byte_array2_.size(), buffer_shrink_threshold));

    auto deserialized_message2 = its_deserializer2->deserialize_message();

    // Desereialize expected to fail.
    ASSERT_EQ(deserialized_message2, nullptr);
}

TEST(deserialize_test, set_data_from_uint8_array_pointer_and_length) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Reversing the byte_array_
    std::array<vsomeip_v3::byte_t, array_size> reverse_byte_array_{byte4, byte3, byte2, byte1};

    // Test Method
    its_deserializer->set_data(reverse_byte_array_.data(), reverse_byte_array_.size());

    // One shot deserialization of the full data.
    std::array<vsomeip_v3::byte_t, array_size> deserialized_byte_array_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_array_.data(), deserialized_byte_array_.size()));

    // Check deserialized data expected values.
    ASSERT_EQ(deserialized_byte_array_.at(0), byte4);
    ASSERT_EQ(deserialized_byte_array_.at(1), byte3);
    ASSERT_EQ(deserialized_byte_array_.at(2), byte2);
    ASSERT_EQ(deserialized_byte_array_.at(3), byte1);

    // Attempt a second try with null array expect data to get cleared and remaining to be 0
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer2(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    its_deserializer2->set_data(nullptr, array_size);

    // Remaining should have been set to 0 and the data cleared.
    ASSERT_EQ(its_deserializer2->get_remaining(), 0);

    // Check deserialize failure.
    ASSERT_FALSE(its_deserializer2->deserialize(deserialized_byte_array_.data(), deserialized_byte_array_.size()));
}

TEST(deserialize_test, set_data_from_uint8_vector) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // One shot deserialization of the full data. Creating a vector with size 4
    std::vector<std::uint8_t> uint8_vector_{byte4, byte3, byte2, byte1, byte4};

    // Test Method
    its_deserializer->set_data(uint8_vector_);

    // Remaining size should be array_size + 1
    ASSERT_EQ(its_deserializer->get_remaining(), array_size + 1);

    // One shot deserialization of the full data.
    std::array<vsomeip_v3::byte_t, array_size + 1> deserialized_byte_array_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_array_.data(), deserialized_byte_array_.size()));

    // Check deserialized data expected values.
    ASSERT_EQ(deserialized_byte_array_.at(0), byte4);
    ASSERT_EQ(deserialized_byte_array_.at(1), byte3);
    ASSERT_EQ(deserialized_byte_array_.at(2), byte2);
    ASSERT_EQ(deserialized_byte_array_.at(3), byte1);
    ASSERT_EQ(deserialized_byte_array_.at(4), byte4);
}

TEST(deserialize_test, append_data_from_uint8_array_pointer_and_length) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Reversing the byte_array_
    std::array<vsomeip_v3::byte_t, array_size> reverse_byte_array_{byte4, byte3, byte2, byte1};

    // Test Method
    its_deserializer->append_data(reverse_byte_array_.data(), reverse_byte_array_.size());

    // Test remaining is twice the array length after appending
    ASSERT_EQ(its_deserializer->get_remaining(), array_size * 2);

    // One shot deserialization of the full data.
    std::array<vsomeip_v3::byte_t, array_size * 2> deserialized_byte_array_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_array_.data(), deserialized_byte_array_.size()));

    // Check deserialized data expected values.
    ASSERT_EQ(deserialized_byte_array_.at(0), deserialized_byte_array_.at(7));
    ASSERT_EQ(deserialized_byte_array_.at(1), deserialized_byte_array_.at(6));
    ASSERT_EQ(deserialized_byte_array_.at(2), deserialized_byte_array_.at(5));
    ASSERT_EQ(deserialized_byte_array_.at(3), deserialized_byte_array_.at(4));
}

TEST(deserialize_test, drop_data) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Test Method.
    its_deserializer->drop_data(1);

    // Deserialize 1 byte expect to get byte2 since we dropped byte1.
    vsomeip_v3::byte_t deserialized_byte_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte2);
    ASSERT_NE(deserialized_byte_, byte1);

    // Test Method.
    its_deserializer->drop_data(1);

    // Deserialize 1 byte expect to get byte4 since we dropped byte3.
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte4);
    ASSERT_NE(deserialized_byte_, byte3);

    // New deserializer to jump 3 spots instead of just 1
    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer2(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Test Method.
    its_deserializer2->drop_data(3);

    // Deserialize 1 byte expect to get byte4 since we dropped byte1 - byte3.
    ASSERT_TRUE(its_deserializer2->deserialize(deserialized_byte_));
    ASSERT_EQ(deserialized_byte_, byte4);
    ASSERT_NE(deserialized_byte_, byte1);
}

TEST(deserialize_test, reset) {
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::deserializer> its_deserializer(
        new vsomeip_v3::deserializer(byte_array_.data(), byte_array_.size(), buffer_shrink_threshold));

    // Deserialize 1 byte expect to get byte2 since we dropped byte1.
    vsomeip_v3::byte_t deserialized_byte_;
    ASSERT_TRUE(its_deserializer->deserialize(deserialized_byte_));

    // Expect remaining size to be 1 less than array size, since we read 1 byte.
    ASSERT_EQ(its_deserializer->get_remaining(), array_size - 1);

    // Test Method.
    its_deserializer->reset();

    // Expect the size to be 0 since the data vector is now empty.
    ASSERT_EQ(its_deserializer->get_remaining(), 0);
}
