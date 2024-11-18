// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include "../../../implementation/message/include/payload_impl.hpp"
#include "../../../implementation/message/include/serializer.hpp"
#include "../../../implementation/utility/include/bithelper.hpp"

namespace {
    const std::uint8_t uint8_num1= 1;
    const std::uint8_t uint8_num2 = 2;
    const std::uint8_t uint8_num3 = 3;
    const std::uint16_t uint16_num1= 1;
    const std::uint16_t uint16_num2 = 2;
    const std::uint16_t uint16_num3 = 3;
    const std::uint32_t uint32_num1= 1;
    const std::uint32_t uint32_num2 = 2;
    const std::uint32_t uint32_num3 = 3;

    bool omit_last_byte = true;
    bool dont_omit_last_byte = false;
}

TEST(serialize_test, serialize_from_serializable_pointer) {
    std::vector<vsomeip_v3::byte_t> data_vector_{uint8_num1, uint8_num2, uint8_num3, uint8_num1};

    auto its_serializable = new vsomeip_v3::payload_impl(data_vector_);

    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    ASSERT_TRUE(its_serializer->serialize(its_serializable));
    ASSERT_EQ(its_serializer->get_size(), 4);
}


TEST(serialize_test, serialize_from_uint8) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    //add 1 2 3 to the data of the serializer.
    ASSERT_TRUE(its_serializer->serialize(uint8_num1));
    ASSERT_TRUE(its_serializer->serialize(uint8_num2));
    ASSERT_TRUE(its_serializer->serialize(uint8_num3));

    ASSERT_EQ(its_serializer->get_data()[0], uint8_num1);
    ASSERT_EQ(its_serializer->get_data()[1], uint8_num2);
    ASSERT_EQ(its_serializer->get_data()[2], uint8_num3);

    ASSERT_EQ(its_serializer->get_size(), 3);
}

TEST(serialize_test, serialize_from_uint16) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    //add 1 2 3 to the data of the serializer.
    ASSERT_TRUE(its_serializer->serialize(uint16_num1));
    ASSERT_TRUE(its_serializer->serialize(uint16_num2));
    ASSERT_TRUE(its_serializer->serialize(uint16_num3));

    // Rebuilding the uint16_t from 2 uint8_t words.
    std::array<vsomeip_v3::byte_t, 2> uint16_array_reconstructed_num1_{its_serializer->get_data()[0], its_serializer->get_data()[1]};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_reconstructed_num2_{its_serializer->get_data()[2], its_serializer->get_data()[3]};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_reconstructed_num3_{its_serializer->get_data()[4], its_serializer->get_data()[5]};

    std::uint16_t reconstructed_num1 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_reconstructed_num1_.data());
    std::uint16_t reconstructed_num2 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_reconstructed_num2_.data());
    std::uint16_t reconstructed_num3 = vsomeip_v3::bithelper::read_uint16_be(uint16_array_reconstructed_num3_.data());

    ASSERT_EQ(reconstructed_num1, uint16_num1);
    ASSERT_EQ(reconstructed_num2, uint16_num2);
    ASSERT_EQ(reconstructed_num3, uint16_num3);

    ASSERT_EQ(its_serializer->get_size(), 6);
}

TEST(serialize_test, serialize_from_uint32_omit_last_byte) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    //add 1 2 3 to the data of the serializer.
    ASSERT_TRUE(its_serializer->serialize(uint32_num1, omit_last_byte));
    ASSERT_TRUE(its_serializer->serialize(uint32_num2, omit_last_byte));
    ASSERT_TRUE(its_serializer->serialize(uint32_num3, omit_last_byte));

    // Rebuilding the uint32_t from 3 uint8_t words, since 4th byte is omited.
    // Create arrays to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_array_reconstructed_num1_{0, its_serializer->get_data()[0], its_serializer->get_data()[1], its_serializer->get_data()[2]};
    std::array<vsomeip_v3::byte_t, 4> uint32_array_reconstructed_num2_{0, its_serializer->get_data()[3], its_serializer->get_data()[4], its_serializer->get_data()[5]};
    std::array<vsomeip_v3::byte_t, 4> uint32_array_reconstructed_num3_{0, its_serializer->get_data()[6], its_serializer->get_data()[7], its_serializer->get_data()[8]};

    // Create uint32_t from bytes.
    const std::uint32_t reconstructed_num1 = vsomeip_v3::bithelper::read_uint32_be(uint32_array_reconstructed_num1_.data());
    const std::uint32_t reconstructed_num2 = vsomeip_v3::bithelper::read_uint32_be(uint32_array_reconstructed_num2_.data());
    const std::uint32_t reconstructed_num3 = vsomeip_v3::bithelper::read_uint32_be(uint32_array_reconstructed_num3_.data());

    ASSERT_EQ(reconstructed_num1, uint32_num1);
    ASSERT_EQ(reconstructed_num2, uint32_num2);
    ASSERT_EQ(reconstructed_num3, uint32_num3);

    ASSERT_EQ(its_serializer->get_size(), 9);
}

TEST(serialize_test, serialize_from_uint32_dont_omit_last_byte) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    //add 1 2 3 to the data of the serializer.
    ASSERT_TRUE(its_serializer->serialize(uint32_num1, dont_omit_last_byte));
    ASSERT_TRUE(its_serializer->serialize(uint32_num2, dont_omit_last_byte));
    ASSERT_TRUE(its_serializer->serialize(uint32_num3, dont_omit_last_byte));

    // Rebuilding the uint32_t from 4 uint8_t words.
    // Create arrays to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_array_reconstructed_num1_{its_serializer->get_data()[0], its_serializer->get_data()[1], its_serializer->get_data()[2], its_serializer->get_data()[3]};
    std::array<vsomeip_v3::byte_t, 4> uint32_array_reconstructed_num2_{its_serializer->get_data()[4], its_serializer->get_data()[5], its_serializer->get_data()[6], its_serializer->get_data()[7]};
    std::array<vsomeip_v3::byte_t, 4> uint32_array_reconstructed_num3_{its_serializer->get_data()[8], its_serializer->get_data()[9], its_serializer->get_data()[10], its_serializer->get_data()[11]};

    // Create uint32_t from bytes.
    const std::uint32_t reconstructed_num1 = vsomeip_v3::bithelper::read_uint32_be(uint32_array_reconstructed_num1_.data());
    const std::uint32_t reconstructed_num2 = vsomeip_v3::bithelper::read_uint32_be(uint32_array_reconstructed_num2_.data());
    const std::uint32_t reconstructed_num3 = vsomeip_v3::bithelper::read_uint32_be(uint32_array_reconstructed_num3_.data());

    ASSERT_EQ(reconstructed_num1, uint32_num1);
    ASSERT_EQ(reconstructed_num2, uint32_num2);
    ASSERT_EQ(reconstructed_num3, uint32_num3);

    ASSERT_EQ(its_serializer->get_size(), 12);
}

TEST(serialize_test, serialize_from_uint8_array_with_length) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));
    std::vector<std::uint8_t> data_{uint8_num1, uint8_num2, uint8_num3};

    ASSERT_TRUE(its_serializer->serialize(data_.data(), static_cast<std::uint32_t>(data_.size())));

    ASSERT_EQ(its_serializer->get_data()[0], uint8_num1);
    ASSERT_EQ(its_serializer->get_data()[1], uint8_num2);
    ASSERT_EQ(its_serializer->get_data()[2], uint8_num3);

    ASSERT_EQ(its_serializer->get_size(), 3);
}

TEST(serialize_test, serializer_get_capacity) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    ASSERT_GT(its_serializer->get_capacity(), 0);
}

TEST(serialize_test, serializer_get_size) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    ASSERT_EQ(its_serializer->get_size(), 0);
    ASSERT_TRUE(its_serializer->serialize(uint8_num1));
    ASSERT_EQ(its_serializer->get_size(), 1);
    ASSERT_TRUE(its_serializer->serialize(uint8_num2));
    ASSERT_EQ(its_serializer->get_size(), 2);
    ASSERT_TRUE(its_serializer->serialize(uint8_num3));
    ASSERT_EQ(its_serializer->get_size(), 3);
}

TEST(serialize_test, serializer_reset) {
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    ASSERT_EQ(its_serializer->get_size(), 0);
    ASSERT_TRUE(its_serializer->serialize(uint8_num1));
    ASSERT_TRUE(its_serializer->serialize(uint8_num2));
    ASSERT_TRUE(its_serializer->serialize(uint8_num3));
    ASSERT_EQ(its_serializer->get_size(), 3);

    its_serializer->reset();
    ASSERT_EQ(its_serializer->get_size(), 0);
}

TEST(serialize_test, serializer_reset_shrink) {
    //Not sure how this is supposed to go.
    std::unique_ptr<vsomeip_v3::serializer> its_serializer(new vsomeip_v3::serializer(1));

    ASSERT_TRUE(its_serializer->serialize(uint8_num1));
    ASSERT_TRUE(its_serializer->serialize(uint8_num2));
    ASSERT_TRUE(its_serializer->serialize(uint8_num3));
    ASSERT_EQ(its_serializer->get_size(), 3);

    its_serializer->reset();

    ASSERT_TRUE(its_serializer->serialize(uint8_num1));
    ASSERT_TRUE(its_serializer->serialize(uint8_num2));
    ASSERT_TRUE(its_serializer->serialize(uint8_num3));
    ASSERT_EQ(its_serializer->get_size(), 3);

    its_serializer->reset();
    ASSERT_EQ(its_serializer->get_size(), 0);
}
