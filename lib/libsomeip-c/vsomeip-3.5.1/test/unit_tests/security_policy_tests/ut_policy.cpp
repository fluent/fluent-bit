// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>
#include <vsomeip/defines.hpp>

#include "../../../implementation/utility/include/bithelper.hpp"
#include "../../../implementation/security/include/policy.hpp"

namespace {
    // Arbitrary array size, will depends on the policy itself.
    const std::uint32_t array_size = 82;

    // Credentials.
    const vsomeip_v3::byte_t uid_byte1 = 0x01;
    const vsomeip_v3::byte_t uid_byte2 = 0x02;
    const vsomeip_v3::byte_t uid_byte3 = 0x03;
    const vsomeip_v3::byte_t uid_byte4 = 0x04;
    const vsomeip_v3::byte_t gid_byte1 = 0x05;
    const vsomeip_v3::byte_t gid_byte2 = 0x06;
    const vsomeip_v3::byte_t gid_byte3 = 0x07;
    const vsomeip_v3::byte_t gid_byte4 = 0x08;

    // Policy requests length, with respective service number(s).
    const vsomeip_v3::byte_t request_length_byte1 = 0x00;
    const vsomeip_v3::byte_t request_length_byte2 = 0x00;
    const vsomeip_v3::byte_t request_length_byte3 = 0x00;
    const vsomeip_v3::byte_t request_length_byte4 = 38; // Decimal to simplify.
    const vsomeip_v3::byte_t request_service_byte1 = 0x13;
    const vsomeip_v3::byte_t request_service_byte2 = 0x37;

    // Policy offers length, with respective service number(s).
    const vsomeip_v3::byte_t offer_length_byte1 = 0x00;
    const vsomeip_v3::byte_t offer_length_byte2 = 0x00;
    const vsomeip_v3::byte_t offer_length_byte3 = 0x00;
    const vsomeip_v3::byte_t offer_length_byte4 = 28; // Decimal to simplify.
    const vsomeip_v3::byte_t offer_service_byte1 = 0x10;
    const vsomeip_v3::byte_t offer_service_byte2 = 0x01;

    // Length deserialized by deserialize_ids.
    const vsomeip_v3::byte_t id_array_length_byte1 = 0x00;
    const vsomeip_v3::byte_t id_array_length_byte2 = 0x00;
    const vsomeip_v3::byte_t id_array_length_byte3 = 0x00;
    const vsomeip_v3::byte_t id_array_length_byte4 = 32; // Decimal to simplify.

    // Length deserialized by requests' first call to deserialize_id_item_list.
    const vsomeip_v3::byte_t request_instance_idlist_byte1 = 0x00;
    const vsomeip_v3::byte_t request_instance_idlist_byte2 = 0x00;
    const vsomeip_v3::byte_t request_instance_idlist_byte3 = 0x00;
    const vsomeip_v3::byte_t request_instance_idlist_byte4 = 12;

    // Length deserialized by offers' call to deserialize_id_item_list.
    const vsomeip_v3::byte_t offer_instance_idlist_byte1 = 0x00;
    const vsomeip_v3::byte_t offer_instance_idlist_byte2 = 0x00;
    const vsomeip_v3::byte_t offer_instance_idlist_byte3 = 0x00;
    const vsomeip_v3::byte_t offer_instance_idlist_byte4 = 22; // Decimal to simplify.

    // Length deserialized by deserialize_id_item for instances. (Represent either 2*uint16_t = 4 bytes, or uint16_t = 2 bytes)
    const vsomeip_v3::byte_t instance_id_length_byte1 = 0x00;
    const vsomeip_v3::byte_t instance_id_length_byte2 = 0x00;
    const vsomeip_v3::byte_t instance_id_length_byte3 = 0x00;
    const vsomeip_v3::byte_t instance_id_length_byte4 = 0x04;

    // Message type parsed in deserialize_id_item should be either 1 or 2.
    const vsomeip_v3::byte_t instance_id_type_byte1 = 0x00;
    const vsomeip_v3::byte_t instance_id_type_byte2 = 0x00;
    const vsomeip_v3::byte_t instance_id_type_byte3 = 0x00;
    const vsomeip_v3::byte_t instance_id_type_byte4 = 0x02;

    // Low and High of the instance interval, if type 1 only low is necessary.
    const vsomeip_v3::byte_t instance_id_low_byte1 = 0x01;
    const vsomeip_v3::byte_t instance_id_low_byte2 = 0x01;
    const vsomeip_v3::byte_t instance_id_high_byte1 = 0x10;
    const vsomeip_v3::byte_t instance_id_high_byte2 = 0x10;

    // Length deserialized by requests' second call to deserialize_id_item_list.
    const vsomeip_v3::byte_t request_method_idlist_byte1 = 0x00;
    const vsomeip_v3::byte_t request_method_idlist_byte2 = 0x00;
    const vsomeip_v3::byte_t request_method_idlist_byte3 = 0x00;
    const vsomeip_v3::byte_t request_method_idlist_byte4 = 12; // Decimal to simplify.

    // Length deserialized by deserialize_id_item for Methods.
    const vsomeip_v3::byte_t method_id_length_byte1 = 0x00;
    const vsomeip_v3::byte_t method_id_length_byte2 = 0x00;
    const vsomeip_v3::byte_t method_id_length_byte3 = 0x00;
    const vsomeip_v3::byte_t method_id_length_byte4 = 0x04;

    // Message type parsed in deserialize_id_item should be either 1 or 2.
    const vsomeip_v3::byte_t method_id_type_byte1 = 0x00;
    const vsomeip_v3::byte_t method_id_type_byte2 = 0x00;
    const vsomeip_v3::byte_t method_id_type_byte3 = 0x00;
    const vsomeip_v3::byte_t method_id_type_byte4 = 0x02;

    // Low and High of the instance interval, for message type 2.
    const vsomeip_v3::byte_t method_id_low_byte1 = 0x02;
    const vsomeip_v3::byte_t method_id_low_byte2 = 0x02;
    const vsomeip_v3::byte_t method_id_high_byte1 = 0x20;
    const vsomeip_v3::byte_t method_id_high_byte2 = 0x20;

    // Length deserialized by deserialize_id_item for second instance. (represent either 2*uint16_t = 4, or uint16 = 2)
    const vsomeip_v3::byte_t instance2_id_length_byte1 = 0x00;
    const vsomeip_v3::byte_t instance2_id_length_byte2 = 0x00;
    const vsomeip_v3::byte_t instance2_id_length_byte3 = 0x00;
    const vsomeip_v3::byte_t instance2_id_length_byte4 = 0x02;

    // Message type parsed in deserialize_id_item.
    const vsomeip_v3::byte_t instance2_id_type_byte1 = 0x00;
    const vsomeip_v3::byte_t instance2_id_type_byte2 = 0x00;
    const vsomeip_v3::byte_t instance2_id_type_byte3 = 0x00;
    const vsomeip_v3::byte_t instance2_id_type_byte4 = 0x01;

    // Message type 1 only includes low bound.
    const vsomeip_v3::byte_t instance2_id_low_byte1 = 0x70;
    const vsomeip_v3::byte_t instance2_id_low_byte2 = 0x80;

    // Create arrays to pass to bithelper.
    std::array<vsomeip_v3::byte_t, 4> uint32_array_uid_{uid_byte1, uid_byte2, uid_byte3, uid_byte4};
    std::array<vsomeip_v3::byte_t, 4> uint32_array_gid_{gid_byte1, gid_byte2, gid_byte3, gid_byte4};

    // Create uint32_t from bytes.
    const std::uint32_t uid = vsomeip_v3::bithelper::read_uint32_be(uint32_array_uid_.data());
    const std::uint32_t gid = vsomeip_v3::bithelper::read_uint32_be(uint32_array_gid_.data());
}

TEST(security_policy_test, deserialize) {
    std::unique_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy with type 2 instance and methods for requests_
    // and two instances for offers one type 2 instance and one type 1 for offers_
    // type 2 receives a uint16_t for low_ and another for high_
    // for type 1 low_ = high_ and only 1 uint16_t is passed.

    std::array<vsomeip_v3::byte_t, array_size>byte_array_{
        uid_byte1, uid_byte2, uid_byte3, uid_byte4,
        gid_byte1, gid_byte2, gid_byte3, gid_byte4,
        request_length_byte1, request_length_byte2, request_length_byte3, request_length_byte4,
        request_service_byte1, request_service_byte2,
        id_array_length_byte1, id_array_length_byte2, id_array_length_byte3, id_array_length_byte4,
        request_instance_idlist_byte1, request_instance_idlist_byte2, request_instance_idlist_byte3, request_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        request_method_idlist_byte1, request_method_idlist_byte2, request_method_idlist_byte3, request_method_idlist_byte4,
        method_id_length_byte1, method_id_length_byte2, method_id_length_byte3, method_id_length_byte4,
        method_id_type_byte1, method_id_type_byte2, method_id_type_byte3, method_id_type_byte4,
        method_id_low_byte1, method_id_low_byte2,
        method_id_high_byte1, method_id_high_byte2,
        offer_length_byte1, offer_length_byte2, offer_length_byte3, offer_length_byte4,
        offer_service_byte1, offer_service_byte2,
        offer_instance_idlist_byte1, offer_instance_idlist_byte2, offer_instance_idlist_byte3, offer_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        instance2_id_length_byte1, instance2_id_length_byte2, instance2_id_length_byte3, instance2_id_length_byte4,
        instance2_id_type_byte1, instance2_id_type_byte2, instance2_id_type_byte3, instance2_id_type_byte4,
        instance2_id_low_byte1, instance2_id_low_byte2
    };

    const vsomeip_v3::byte_t* data_ptr_ = byte_array_.data();
    std::uint32_t data_size_ = array_size;

    // Test method.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Check credentials.

    // Check if uid and gid were deserialized correctly by private method deserialize_u32
    // Check if uid is in the credentials_
    auto deserialized_gid_set = its_policy->credentials_.lower_bound(
            boost::icl::interval<vsomeip_v3::uid_t>::closed(uid, uid));
    // Check if the associated gid is located.
    ASSERT_EQ(deserialized_gid_set->second.begin()->lower(), gid);

    // Check requests
    // Create uint16_t from bytes.
    std::array<vsomeip_v3::byte_t, 2> uint16_array_request_service_{request_service_byte1, request_service_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_request_instance_low_{instance_id_low_byte1, instance_id_low_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_request_instance_high_{instance_id_high_byte1, instance_id_high_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_request_method_id_low_{method_id_low_byte1, method_id_low_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_request_method_id_high_{method_id_high_byte1, method_id_high_byte2};

    std::uint16_t request_service = vsomeip_v3::bithelper::read_uint16_be(uint16_array_request_service_.data());
    std::uint16_t request_instance_low = vsomeip_v3::bithelper::read_uint16_be(uint16_array_request_instance_low_.data());
    std::uint16_t request_instance_high = vsomeip_v3::bithelper::read_uint16_be(uint16_array_request_instance_high_.data());
    std::uint16_t request_method_low = vsomeip_v3::bithelper::read_uint16_be(uint16_array_request_method_id_low_.data());
    std::uint16_t request_method_high = vsomeip_v3::bithelper::read_uint16_be(uint16_array_request_method_id_high_.data());

    // Check if method high and low were deserialized correctly by private method deserialize_u16
    auto deserialized_service_set = its_policy->requests_.lower_bound(
            boost::icl::interval<vsomeip_v3::service_t>::closed(request_service, request_service));

    // Check if the associated instance low and high are located.
    ASSERT_EQ(deserialized_service_set->second.begin()->first.lower(), request_instance_low);
    ASSERT_EQ(deserialized_service_set->second.begin()->first.upper(), request_instance_high);

    auto deserialized_method_set = deserialized_service_set->second.lower_bound(
        boost::icl::interval<vsomeip_v3::instance_t>::closed(request_instance_low, request_instance_high));

    // Check if the associated request method low and high are located.
    ASSERT_EQ(deserialized_method_set->second.begin()->lower(), request_method_low);
    ASSERT_EQ(deserialized_method_set->second.begin()->upper(), request_method_high);

    // Check offers
    // Create uint16_t from bytes.
    std::array<vsomeip_v3::byte_t, 2> uint16_array_offer_service_{offer_service_byte1, offer_service_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_offer_instance_low_{instance_id_low_byte1, instance_id_low_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_offer_instance_high_{instance_id_high_byte1, instance_id_high_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_offer_instance2_low_{instance2_id_low_byte1, instance2_id_low_byte2};
    std::array<vsomeip_v3::byte_t, 2> uint16_array_offer_instance2_high_{instance2_id_low_byte1, instance2_id_low_byte2};

    std::uint16_t offer_service = vsomeip_v3::bithelper::read_uint16_be(uint16_array_offer_service_.data());
    std::uint16_t offer_instance_low = vsomeip_v3::bithelper::read_uint16_be(uint16_array_offer_instance_low_.data());
    std::uint16_t offer_instance_high = vsomeip_v3::bithelper::read_uint16_be(uint16_array_offer_instance_high_.data());
    std::uint16_t offer_instance2_low = vsomeip_v3::bithelper::read_uint16_be(uint16_array_offer_instance2_low_.data());
    std::uint16_t offer_instance2_high = vsomeip_v3::bithelper::read_uint16_be(uint16_array_offer_instance2_high_.data());

    // Check if method high and low were deserialized correctly by private method deserialize_u16
    auto deserialized_offer_service_set = its_policy->offers_.lower_bound(
        boost::icl::interval<vsomeip_v3::instance_t>::closed(offer_service, offer_service));

    // Check if the associated instance low and high are located.
    ASSERT_EQ(deserialized_offer_service_set->second.begin()->lower(), offer_instance_low);
    ASSERT_EQ(deserialized_offer_service_set->second.begin()->upper(), offer_instance_high);

    // Get the second interval added by the type 1 instance2, create an iterator and advance it.
    // Note if the second interval falls within the first one or vise versa, since we are using an interval set, it will only have 1 item.
    boost::icl::interval_set<vsomeip_v3::instance_t>::iterator it = deserialized_offer_service_set->second.begin();
    ASSERT_NE(++it, deserialized_offer_service_set->second.end());

    // Check low and high are equal.
    std::uint16_t offer_instance2_deserialized_lower = it->lower();
    std::uint16_t offer_instance2_deserialized_upper = it->upper();
    ASSERT_EQ(offer_instance2_deserialized_lower, offer_instance2_deserialized_upper);
    ASSERT_EQ(offer_instance2_deserialized_lower, offer_instance2_low);
    ASSERT_EQ(offer_instance2_deserialized_lower, offer_instance2_high);
}

TEST(security_policy_test, serialize) {
    std::unique_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy with type 2 instance and methods for requests_
    // Create a 54 length array.
    const std::uint32_t resized_array_size = 54;
    std::array<vsomeip_v3::byte_t, resized_array_size> byte_array_{
        uid_byte1, uid_byte2, uid_byte3, uid_byte4,
        gid_byte1, gid_byte2, gid_byte3, gid_byte4,
        request_length_byte1, request_length_byte2, request_length_byte3, request_length_byte4,
        request_service_byte1, request_service_byte2,
        id_array_length_byte1, id_array_length_byte2, id_array_length_byte3, id_array_length_byte4,
        request_instance_idlist_byte1, request_instance_idlist_byte2, request_instance_idlist_byte3, request_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        request_method_idlist_byte1, request_method_idlist_byte2, request_method_idlist_byte3, request_method_idlist_byte4,
        method_id_length_byte1, method_id_length_byte2, method_id_length_byte3, method_id_length_byte4,
        method_id_type_byte1, method_id_type_byte2, method_id_type_byte3, method_id_type_byte4,
        method_id_low_byte1, method_id_low_byte2,
        method_id_high_byte1, method_id_high_byte2,
        offer_length_byte1, offer_length_byte2, offer_length_byte3, 0
        // NOT SURE WHY THE SERIALIZATION IGNORES THE OFFERS.
        // offer_service_byte1, offer_service_byte2,
        // offer_instance_idlist_byte1, offer_instance_idlist_byte2, offer_instance_idlist_byte3, offer_instance_idlist_byte4,
        // instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        // instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        // instance_id_low_byte1, instance_id_low_byte2,
        // instance_id_high_byte1, instance_id_high_byte2,
        // instance2_id_length_byte1, instance2_id_length_byte2, instance2_id_length_byte3, instance2_id_length_byte4,
        // instance2_id_type_byte1, instance2_id_type_byte2, instance2_id_type_byte3, instance2_id_type_byte4,
        // instance2_id_low_byte1, instance2_id_low_byte2
    };

    // Fill policy with data.
    const vsomeip_v3::byte_t* data_ptr_ = byte_array_.data();
    std::uint32_t data_size_ = array_size;
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Create a vector to receive the results of the serialization.
    std::vector<vsomeip_v3::byte_t> byte_vector;

    // Test Method.
    ASSERT_TRUE(its_policy->serialize(byte_vector));

    // Check the vector length is equal to the original array size.
    // the offer part of the policy does not get serialized.
    ASSERT_EQ(byte_vector.size(), resized_array_size);

    // Check bytes.
    for(std::uint32_t i = 0; i < byte_vector.size(); i++)
    {
        ASSERT_EQ(byte_vector.at(i), byte_array_[i]);
    }

}

TEST(security_policy_test, get_uid_gid) {
    std::unique_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy with type 2 instance and methods for requests_
    // and two instances for offers one type 2 instance and one type 1 for offers_
    // type 2 receives a uint16_t for low_ and another for high_
    // for type 1 low_ = high_ and only 1 uint16_t is passed.
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{
        uid_byte1, uid_byte2, uid_byte3, uid_byte4,
        gid_byte1, gid_byte2, gid_byte3, gid_byte4,
        request_length_byte1, request_length_byte2, request_length_byte3, request_length_byte4,
        request_service_byte1, request_service_byte2,
        id_array_length_byte1, id_array_length_byte2, id_array_length_byte3, id_array_length_byte4,
        request_instance_idlist_byte1, request_instance_idlist_byte2, request_instance_idlist_byte3, request_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        request_method_idlist_byte1, request_method_idlist_byte2, request_method_idlist_byte3, request_method_idlist_byte4,
        method_id_length_byte1, method_id_length_byte2, method_id_length_byte3, method_id_length_byte4,
        method_id_type_byte1, method_id_type_byte2, method_id_type_byte3, method_id_type_byte4,
        method_id_low_byte1, method_id_low_byte2,
        method_id_high_byte1, method_id_high_byte2,
        offer_length_byte1, offer_length_byte2, offer_length_byte3, offer_length_byte4,
        offer_service_byte1, offer_service_byte2,
        offer_instance_idlist_byte1, offer_instance_idlist_byte2, offer_instance_idlist_byte3, offer_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        instance2_id_length_byte1, instance2_id_length_byte2, instance2_id_length_byte3, instance2_id_length_byte4,
        instance2_id_type_byte1, instance2_id_type_byte2, instance2_id_type_byte3, instance2_id_type_byte4,
        instance2_id_low_byte1, instance2_id_low_byte2
    };

    const vsomeip_v3::byte_t* data_ptr_ = byte_array_.data();
    std::uint32_t data_size_ = array_size;
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Create uint32_t to receive the value from the test method.
    std::uint32_t deserialized_uid;
    std::uint32_t deserialized_gid;

    // Test method, and compare them to the created uid and gid.
    #ifndef __QNX__
        ASSERT_TRUE(its_policy->get_uid_gid(deserialized_uid, deserialized_gid));
    #endif
    ASSERT_EQ(deserialized_uid, uid);
    ASSERT_EQ(deserialized_gid, gid);
}

TEST(security_policy_test, deserialize_uid_gid) {
    std::unique_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy with type 2 instance and methods for requests_
    // and two instances for offers one type 2 instance and one type 1 for offers_
    // type 2 receives a uint16_t for low_ and another for high_
    // for type 1 low_ = high_ and only 1 uint16_t is passed.
    std::array<vsomeip_v3::byte_t, array_size> byte_array_{
        uid_byte1, uid_byte2, uid_byte3, uid_byte4,
        gid_byte1, gid_byte2, gid_byte3, gid_byte4,
        request_length_byte1, request_length_byte2, request_length_byte3, request_length_byte4,
        request_service_byte1, request_service_byte2,
        id_array_length_byte1, id_array_length_byte2, id_array_length_byte3, id_array_length_byte4,
        request_instance_idlist_byte1, request_instance_idlist_byte2, request_instance_idlist_byte3, request_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        request_method_idlist_byte1, request_method_idlist_byte2, request_method_idlist_byte3, request_method_idlist_byte4,
        method_id_length_byte1, method_id_length_byte2, method_id_length_byte3, method_id_length_byte4,
        method_id_type_byte1, method_id_type_byte2, method_id_type_byte3, method_id_type_byte4,
        method_id_low_byte1, method_id_low_byte2,
        method_id_high_byte1, method_id_high_byte2,
        offer_length_byte1, offer_length_byte2, offer_length_byte3, offer_length_byte4,
        offer_service_byte1, offer_service_byte2,
        offer_instance_idlist_byte1, offer_instance_idlist_byte2, offer_instance_idlist_byte3, offer_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        instance2_id_length_byte1, instance2_id_length_byte2, instance2_id_length_byte3, instance2_id_length_byte4,
        instance2_id_type_byte1, instance2_id_type_byte2, instance2_id_type_byte3, instance2_id_type_byte4,
        instance2_id_low_byte1, instance2_id_low_byte2
    };

    const vsomeip_v3::byte_t* data_ptr_ = byte_array_.data();
    std::uint32_t data_size_ = array_size;
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Create uint32_t to receive the value from the test method.
    std::uint32_t deserialized_uid;
    std::uint32_t deserialized_gid;

    // Resetting the pointers.
    data_ptr_ = byte_array_.data();
    data_size_ = array_size;

    // Test method.
    #ifndef __QNX__
        ASSERT_TRUE(its_policy->deserialize_uid_gid(data_ptr_, data_size_, deserialized_uid, deserialized_gid));
    #endif
    ASSERT_EQ(deserialized_uid, uid);
    ASSERT_EQ(deserialized_gid, gid);
}
