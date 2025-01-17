// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include "../../../implementation/message/include/deserializer.hpp"
#include "../../../implementation/message/include/payload_impl.hpp"
#include "../../../implementation/message/include/serializer.hpp"

namespace {
    const std::uint8_t array_size = 4;
    const std::uint32_t buffer_shrink_threshold = 1;
    const vsomeip_v3::byte_t byte1 = 1;
    const vsomeip_v3::byte_t byte2 = 2;
    const vsomeip_v3::byte_t byte3 = 3;
    const vsomeip_v3::byte_t byte4 = 4;

}

TEST(payload_impl_test, equalequal_operator) {
    // Create test data.
    std::vector<std::uint8_t> data_vector_{byte1, byte2, byte3, byte4};

    vsomeip_v3::payload_impl its_payload_impl(data_vector_);

    std::vector<std::uint8_t> data_vector2_{byte1, byte2, byte3, byte4};

    vsomeip_v3::payload_impl its_similar_payload_impl(data_vector2_);

    std::vector<std::uint8_t> data_vector3_{byte4, byte3, byte2, byte1};

    vsomeip_v3::payload_impl its_different_payload_impl(data_vector3_);

    // Checks.
    ASSERT_TRUE(its_payload_impl == its_similar_payload_impl);
    ASSERT_FALSE(its_payload_impl == its_different_payload_impl);
}

TEST(payload_impl_test, set_data) {
    // Create test data.
    std::vector<vsomeip_v3::byte_t> data_vector_{byte1, byte2, byte3, byte4};

    std::array<std::uint8_t, array_size> data_array_{byte1, byte2, byte3, byte4};

    vsomeip_v3::payload_impl its_payload_impl1;
    vsomeip_v3::payload_impl its_payload_impl2;
    vsomeip_v3::payload_impl its_payload_impl3;

    // Test methods.
    its_payload_impl1.set_data(data_vector_);
    its_payload_impl2.set_data(data_array_.data(), data_array_.size());
    its_payload_impl3.set_data(std::move(data_vector_));

    // Checks.
    ASSERT_TRUE(its_payload_impl1 == its_payload_impl2);
    ASSERT_TRUE(its_payload_impl1 == its_payload_impl3);
}

TEST(payload_impl_test, constructors) {
    // Create test data.
    std::vector<std::uint8_t> data_vector_{byte1, byte2, byte3, byte4};

    std::array<std::uint8_t, array_size> data_array_{byte1, byte2, byte3, byte4};

    // Test Overloaded constructors.
    vsomeip_v3::payload_impl its_payload_impl1;
    // Add data to the empty data.
    its_payload_impl1.set_data(data_vector_);

    vsomeip_v3::payload_impl its_payload_impl2(data_vector_);
    vsomeip_v3::payload_impl its_payload_impl3(data_array_.data(), data_array_.size());
    vsomeip_v3::payload_impl its_payload_impl4(its_payload_impl1);

    // Checks.
    ASSERT_TRUE(its_payload_impl1 == its_payload_impl2);
    ASSERT_TRUE(its_payload_impl1 == its_payload_impl3);
    ASSERT_TRUE(its_payload_impl1 == its_payload_impl4);
}

TEST(payload_impl_test, get_length) {
    // Create test data.
    std::array<std::uint8_t, array_size> data_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::payload_impl> its_payload_impl(new vsomeip_v3::payload_impl(data_array_.data(), data_array_.size()));

    // Test method.
    ASSERT_EQ(its_payload_impl->get_length(), array_size);
}

TEST(payload_impl_test, serialize) {
    // Create test data.
    std::array<std::uint8_t, array_size> data_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::payload_impl> its_payload_impl(new vsomeip_v3::payload_impl(data_array_.data(), data_array_.size()));
    vsomeip_v3::serializer its_serializer(buffer_shrink_threshold);

    // Test method.
    ASSERT_TRUE(its_payload_impl->serialize(&its_serializer));

    // Checks.
    ASSERT_EQ(its_payload_impl->get_data()[0], its_serializer.get_data()[0]);
    ASSERT_EQ(its_payload_impl->get_data()[1], its_serializer.get_data()[1]);
    ASSERT_EQ(its_payload_impl->get_data()[2], its_serializer.get_data()[2]);
    ASSERT_EQ(its_payload_impl->get_data()[3], its_serializer.get_data()[3]);
}

TEST(payload_impl_test, deserialize) {
    // Create test data.
    std::array<std::uint8_t, array_size> data_array_{byte1, byte2, byte3, byte4};

    std::unique_ptr<vsomeip_v3::payload_impl> its_payload_impl(new vsomeip_v3::payload_impl());
    vsomeip_v3::deserializer its_deserializer(data_array_.data(), data_array_.size(), buffer_shrink_threshold);

    // Test set_capacity at the same time.
    its_payload_impl->set_capacity(array_size);

    // Test Method.
    ASSERT_TRUE(its_payload_impl->deserialize(&its_deserializer));

    // Checks.
    ASSERT_EQ(its_payload_impl->get_length(), array_size);
    ASSERT_EQ(its_payload_impl->get_data()[0], data_array_[0]);
    ASSERT_EQ(its_payload_impl->get_data()[1], data_array_[1]);
    ASSERT_EQ(its_payload_impl->get_data()[2], data_array_[2]);
    ASSERT_EQ(its_payload_impl->get_data()[3], data_array_[3]);
}
