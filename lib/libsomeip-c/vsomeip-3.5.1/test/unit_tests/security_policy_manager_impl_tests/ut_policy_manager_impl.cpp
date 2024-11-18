// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifdef _WIN32
#include <Windows.h>
#endif

#include <gtest/gtest.h>
#include <vsomeip/defines.hpp>

#include <boost/property_tree/ptree.hpp>

#include "../../../implementation/configuration/include/configuration_element.hpp"
#include "../../../implementation/security/include/policy.hpp"
#include "../../../implementation/security/include/policy_manager_impl.hpp"
#include "../../../implementation/utility/include/bithelper.hpp"
#include "../../../implementation/utility/include/utility.hpp"

#include "policy_manager_impl_unit_test_macro.hpp"

namespace {
    // Lazy load.
    bool lazy_load = true;
    bool not_lazy_load = false;

    // Client uint16_t
    const vsomeip_v3::client_t client_number = 0x1000;
    const vsomeip_v3::service_t service_number = 0x1337;
    const vsomeip_v3::service_t offer_service_number = 0x1001;
    const vsomeip_v3::instance_t instance_number = 0x0101;
    const vsomeip_v3::instance_t offer_instance_number = 0x7080;
    const vsomeip_v3::method_t method_number = 0x0202;

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

TEST(security_policy_manager_test, load) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // is_audit returns !check_credentials_ which is by default false, so is_audit should return true.
    ASSERT_TRUE(its_policy_manager->is_audit());

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Test Method. Load policy element, which should set check_credentials to true.
    its_policy_manager->load(its_element, lazy_load);

    // Check that is_audit now returns false. Since check_credentials should now be true if the load worked.
    ASSERT_FALSE(its_policy_manager->is_audit());
}

TEST(security_policy_manager_test, check_credentials) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Default test structure, case will fall through the logic checks to the end of the test method.
    vsomeip_sec_client_t its_client_struct_default;

    its_client_struct_default.user = 0;
    its_client_struct_default.group = 0;
    its_client_struct_default.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct_default.host = 0;

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Test Method, policy not enabled, expect call to return true.
    ASSERT_TRUE(its_policy_manager->check_credentials(client_number, &its_client_struct));

    // Create policy to be able to test the method further.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Add policy to the manager.
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Load policy element, which should set check_credentials to true. Needed to differentiate returns test cases (sets the default test to false).
    its_policy_manager->load(its_element, lazy_load);

    // Test Method, client null expect call to return true.
    ASSERT_TRUE(its_policy_manager->check_credentials(client_number, nullptr));

    // Set port to be different from 0
    its_client_struct.port = 1;

    // Test Method, port != 0, expect call to return true.
    ASSERT_TRUE(its_policy_manager->check_credentials(client_number, &its_client_struct));

    // reset port to 0
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;

    // Test Method, expect call to return true.
    ASSERT_TRUE(its_policy_manager->check_credentials(client_number, &its_client_struct));

    // Test Method, expect call to default through and return !check_credentials. Since we set it to true we expect false.
    ASSERT_FALSE(its_policy_manager->check_credentials(0, &its_client_struct_default));
}

TEST(security_policy_manager_test, check_routing_credentials) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Default test structure, case will fall through the logic checks to the end of the test method.
    vsomeip_sec_client_t its_client_struct_default;

    its_client_struct_default.user = 0;
    its_client_struct_default.group = 0;
    its_client_struct_default.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct_default.host = 0;

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Add policy to the manager.
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Create a policy element setting check_credentials to true. And check_routing_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    boost::property_tree::ptree tree_check_routing_credentials;
    boost::property_tree::ptree tree_check_routing_credentials_uid;
    boost::property_tree::ptree tree_check_routing_credentials_gid;

    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    tree_check_routing_credentials_uid.put_value("0x01020304");
    tree_check_routing_credentials_gid.put_value("0x05060708");
    tree_check_routing_credentials.add_child("uid", tree_check_routing_credentials_uid);
    tree_check_routing_credentials.add_child("gid", tree_check_routing_credentials_gid);
    tree.add_child("routing-credentials", tree_check_routing_credentials);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Test Method, expect call to return true. This method, defaults even with nullptr, no null checks.
    ASSERT_TRUE(its_policy_manager->check_routing_credentials(nullptr));

    // Load policy element not lazy load, to call load_routing_credentials which should set check_routing_credentials_ to true.
    its_policy_manager->load(its_element, not_lazy_load);

    // Test Method, expect call to default through and return !check_routing_credentials. Since we set it to true we expect false.
    ASSERT_FALSE(its_policy_manager->check_routing_credentials(&its_client_struct_default));

    // Test Method, expect call to return true.
    ASSERT_TRUE(its_policy_manager->check_routing_credentials(&its_client_struct));
}

TEST(security_policy_manager_test, set_routing_credentials) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Default test structure, case will fall through the logic checks to the end of the test method.
    vsomeip_sec_client_t its_client_struct_default;

    its_client_struct_default.user = 0;
    its_client_struct_default.group = 0;
    its_client_struct_default.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct_default.host = 0;

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    const std::string routing_name = "random";
    // Test method
    its_policy_manager->set_routing_credentials(uid, gid, routing_name);

    // Test Method, expect call to default through and return !check_routing_credentials. Since it is false by default, we expect true.
    ASSERT_TRUE(its_policy_manager->check_routing_credentials(&its_client_struct_default));

    // Test Method, expect call to return true.
    ASSERT_TRUE(its_policy_manager->check_routing_credentials(&its_client_struct));
}

TEST(security_policy_manager_test, is_client_allowed) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Default test structure, case will fall through the logic checks to the end of the test method.
    vsomeip_sec_client_t its_client_struct_default;

    its_client_struct_default.user = 0;
    its_client_struct_default.group = 0;
    its_client_struct_default.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct_default.host = 0;

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Test Method. Policy not enabled
    ASSERT_TRUE(its_policy_manager->is_client_allowed(&its_client_struct, service_number, instance_number, method_number, true));

    // Enable policy.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Add policy to the manager.
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Load policy element, which should set check_credentials to true. Needed to differentiate returns test cases (sets the default test to false).
    its_policy_manager->load(its_element, lazy_load);

    // Set port to a number different than 0
    its_client_struct.port = 1;
    // Test Method. Expect to receive true since the port is not 0
    ASSERT_TRUE(its_policy_manager->is_client_allowed(&its_client_struct, service_number, instance_number, method_number, true));
    //reset port to 0.
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;

    // Test Method. client is null. Expect !check_credentials.
    ASSERT_FALSE(its_policy_manager->is_client_allowed(nullptr, service_number, instance_number, method_number, true));

    // Test Method. Expect true, is matching is true, and client is added to cache.
    ASSERT_TRUE(its_policy_manager->is_client_allowed(&its_client_struct, service_number, instance_number, method_number, true));

    // Test Method. Expect true, case in cache.
    ASSERT_TRUE(its_policy_manager->is_client_allowed(&its_client_struct, service_number, instance_number, method_number, true));

    // Allow what false.
    its_policy->allow_what_= false;
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Test Method expect true from return where allow what is false.
    ASSERT_TRUE(its_policy_manager->is_client_allowed(&its_client_struct, service_number, instance_number, 1, false));

    // Test method, expect !check_credentials which we set to true, so expect false.
    ASSERT_FALSE(its_policy_manager->is_client_allowed(&its_client_struct_default, service_number, instance_number, method_number, true));
}


TEST(security_policy_manager_test, is_offer_allowed) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Default test structure, case will fall through the logic checks to the end of the test method.
    vsomeip_sec_client_t its_client_struct_default;

    its_client_struct_default.user = 0;
    its_client_struct_default.group = 0;
    its_client_struct_default.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct_default.host = 0;

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Test Method. Policy not enabled
    ASSERT_TRUE(its_policy_manager->is_offer_allowed(&its_client_struct, offer_service_number, offer_instance_number));

    // Enable policy.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Add policy to the manager.
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Load policy element, which should set check_credentials to true. Needed to differentiate returns test cases (sets the default test to false).
    its_policy_manager->load(its_element, lazy_load);

    // Set port to a number different than 0
    its_client_struct.port = 1;
    // Test Method. Expect to receive true since the port is not 0
    ASSERT_TRUE(its_policy_manager->is_offer_allowed(&its_client_struct, offer_service_number, offer_instance_number));
    //reset port to 0.
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;

    // Test Method. client is null. Expect !check_credentials.
    ASSERT_FALSE(its_policy_manager->is_offer_allowed(nullptr, offer_service_number, offer_instance_number));

    // Test Method. Expect true, is matching is true, and client is added to cache.
    ASSERT_TRUE(its_policy_manager->is_offer_allowed(&its_client_struct, offer_service_number, offer_instance_number));

    // Test method, expect !check_credentials which we set to true, so expect false.
    ASSERT_FALSE(its_policy_manager->is_offer_allowed(&its_client_struct_default, offer_service_number, offer_instance_number));
}

TEST(security_policy_manager_test, store_sec_client_to_client_mapping_and_get_sec_client_to_clients_mapping) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    std::set<vsomeip_v3::client_t> client_set;

    // Test method, expect false since sec client is null.
    ASSERT_FALSE(its_policy_manager->get_sec_client_to_clients_mapping(nullptr, client_set));

    // Set client structure port to different than 0.
    its_client_struct.port = 1;
    // Test method expect false since port != 0.
    ASSERT_FALSE(its_policy_manager->get_sec_client_to_clients_mapping(&its_client_struct, client_set));
    // reset port to 0
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;

    // Test method, correct call but expect false since we have yet to add a client to the mapping.
    ASSERT_FALSE(its_policy_manager->get_sec_client_to_clients_mapping(&its_client_struct, client_set));

    // Test method, add a client to the client mapping.
    its_policy_manager->store_sec_client_to_client_mapping(&its_client_struct, client_number);

    // Test method, expect true since the client was added to the mapping.
    ASSERT_TRUE(its_policy_manager->get_sec_client_to_clients_mapping(&its_client_struct, client_set));
}

TEST(security_policy_manager_test, store_client_to_sec_client_mapping) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;


    // Test method, expect false since sec client is null.
    ASSERT_FALSE(its_policy_manager->store_client_to_sec_client_mapping(client_number, nullptr));

    // Set client structure port to different than 0.
    its_client_struct.port = 1;
    // Test method expect false since port != 0.
    ASSERT_FALSE(its_policy_manager->store_client_to_sec_client_mapping(client_number, &its_client_struct));
    // reset port to 0
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;

    // Test method, expect true as we are adding a client.
    ASSERT_TRUE(its_policy_manager->store_client_to_sec_client_mapping(client_number, &its_client_struct));
}

TEST(security_policy_manager_test, get_client_to_sec_client_mapping) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Test method, expect false since we have yet to store a client.
    ASSERT_FALSE(its_policy_manager->get_client_to_sec_client_mapping(client_number, its_client_struct));

    // store a client to client mapping.
    ASSERT_TRUE(its_policy_manager->store_client_to_sec_client_mapping(client_number, &its_client_struct));

    // Test method, expect true since we stored the client previously.
    ASSERT_TRUE(its_policy_manager->get_client_to_sec_client_mapping(client_number, its_client_struct));
}

TEST(security_policy_manager_test, remove_client_to_sec_client_mapping) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Test method, expect false since we have yet to store a client.
    ASSERT_FALSE(its_policy_manager->remove_client_to_sec_client_mapping(client_number));

    // store a client to client mapping.
    ASSERT_TRUE(its_policy_manager->store_client_to_sec_client_mapping(client_number, &its_client_struct));
    its_policy_manager->store_sec_client_to_client_mapping(&its_client_struct, client_number);

    // Test method, expect true since we stored the client previously.
    ASSERT_TRUE(its_policy_manager->remove_client_to_sec_client_mapping(client_number));
}

TEST(security_policy_manager_test, parse_policy) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    std::uint32_t deserialized_uid, deserialized_gid;

    // Test method.
    #ifndef __QNX__
        ASSERT_TRUE(its_policy_manager->parse_policy(data_ptr_, data_size_, deserialized_uid, deserialized_gid, its_policy));
    #endif

    ASSERT_EQ(uid, deserialized_uid);
    ASSERT_EQ(gid, deserialized_gid);

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_too_short[4]{
        uid_byte1, uid_byte2, uid_byte3, uid_byte4
    };

    const vsomeip_v3::byte_t *data_ptr2_ = byte_array_too_short;
    std::uint32_t data_size2_ = 4;

    // Test Method, expect false.
    #ifndef __QNX__
        ASSERT_FALSE(its_policy_manager->parse_policy(data_ptr2_, data_size2_, deserialized_uid, deserialized_gid, its_policy));
    #endif
}

TEST(security_policy_manager_test, parse_uid_gid) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    std::uint32_t deserialized_uid, deserialized_gid;

    // Test method.
    #ifndef __QNX__
        ASSERT_TRUE(its_policy_manager->parse_uid_gid(data_ptr_, data_size_, deserialized_uid, deserialized_gid));
    #endif

    ASSERT_EQ(uid, deserialized_uid);
    ASSERT_EQ(gid, deserialized_gid);

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_too_short[4]{
        uid_byte1, uid_byte2, uid_byte3, uid_byte4
    };

    const vsomeip_v3::byte_t *data_ptr2_ = byte_array_too_short;
    std::uint32_t data_size2_ = 4;

    // Test Method, expect false.
    #ifndef __QNX__
        ASSERT_FALSE(its_policy_manager->parse_uid_gid(data_ptr2_, data_size2_, deserialized_uid, deserialized_gid));
    #endif
}

TEST(security_policy_manager_test, remove_security_policy) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test method. Expect false since no policy was added.
    ASSERT_FALSE(its_policy_manager->remove_security_policy(uid, gid));

    // Add a policy.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Add policy to the manager.
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Test method. Expect true since we added a policy.
    ASSERT_TRUE(its_policy_manager->remove_security_policy(uid, gid));
}

TEST(security_policy_manager_test, add_security_credentials) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Add a policy.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Test method. Add security credentials.
    its_policy_manager->add_security_credentials(uid, gid, its_policy, client_number);

    // Expect true since we added the security credentials policy above.
    ASSERT_TRUE(its_policy_manager->remove_security_policy(uid, gid));
}

TEST(security_policy_manager_test, get_requester_policies) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Add a policy.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    std::shared_ptr<vsomeip_v3::policy> its_policy2(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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
        request_service_byte1, request_service_byte2,
        offer_instance_idlist_byte1, offer_instance_idlist_byte2, offer_instance_idlist_byte3, offer_instance_idlist_byte4,
        instance_id_length_byte1, instance_id_length_byte2, instance_id_length_byte3, instance_id_length_byte4,
        instance_id_type_byte1, instance_id_type_byte2, instance_id_type_byte3, instance_id_type_byte4,
        instance_id_low_byte1, instance_id_low_byte2,
        instance_id_high_byte1, instance_id_high_byte2,
        instance2_id_length_byte1, instance2_id_length_byte2, instance2_id_length_byte3, instance2_id_length_byte4,
        instance2_id_type_byte1, instance2_id_type_byte2, instance2_id_type_byte3, instance2_id_type_byte4,
        instance2_id_low_byte1, instance2_id_low_byte2
    };

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    std::set<std::shared_ptr<vsomeip_v3::policy>> its_policy_set= {};

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Test set is empty.
    ASSERT_TRUE(its_policy_set.empty());

    // Test method.
    its_policy_manager->get_requester_policies(its_policy, its_policy_set);

    // Since the policy was not added to the manager, expect set to be empty still.
    ASSERT_TRUE(its_policy_set.empty());

    // Add policy to manager.
    its_policy_manager->update_security_policy(uid, gid, its_policy);

    // Test method.
    its_policy_manager->get_requester_policies(its_policy, its_policy_set);

    // Expect true because of the continue in the for loops if its_policy is equal to the policy in the manager.
    ASSERT_TRUE(its_policy_set.empty());

    // reseting data.
    data_ptr_ = byte_array_;
    data_size_ = array_size;

    // Set up new policy2.
    ASSERT_TRUE(its_policy2->deserialize(data_ptr_, data_size_));
    its_policy_manager->update_security_policy(uid, gid, its_policy2);

    // Test method.
    its_policy_manager->get_requester_policies(its_policy2, its_policy_set);

    // Expect the set to now be populated.
    ASSERT_FALSE(its_policy_set.empty());
}

TEST(security_policy_manager_test, get_clients) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test Structure.
    vsomeip_sec_client_t its_client_struct;

    its_client_struct.user = uid;
    its_client_struct.group = gid;
    its_client_struct.port = VSOMEIP_SEC_PORT_UNUSED;
    its_client_struct.host = 0;

    // Add a policy.
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    std::unordered_set<vsomeip_v3::client_t> its_client_set= {};

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Assert set is empty.
    ASSERT_TRUE(its_client_set.empty());

    // Test method.
    its_policy_manager->get_clients(uid, gid, its_client_set);

    // Since no client was added, expect the set to remain empty.
    ASSERT_TRUE(its_client_set.empty());

    // Add client to manager.
    ASSERT_TRUE(its_policy_manager->store_client_to_sec_client_mapping(client_number, &its_client_struct));

    // Test method.
    its_policy_manager->get_clients(uid, gid, its_client_set);

    // Expect false since we added a client to the manager.
    ASSERT_FALSE(its_client_set.empty());
    ASSERT_EQ(its_client_set.size(), 1);

    // Add client to manager.
    ASSERT_TRUE(its_policy_manager->store_client_to_sec_client_mapping(client_number + 1, &its_client_struct));

    // test method.
    its_policy_manager->get_clients(uid, gid, its_client_set);

    // Expect set to have 2 entries.
    ASSERT_EQ(its_client_set.size(), 2);
}

TEST(security_policy_manager_test, get_policy_extension_path) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    const std::string its_client_host = "random";

    // Test Method.
    ASSERT_EQ(its_policy_manager->get_policy_extension_path(its_client_host), "");

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    boost::property_tree::ptree tree_container_policy_extensions;
    boost::property_tree::ptree tree_container_policy_extension;
    boost::property_tree::ptree tree_container_policy_extensions_container;
    boost::property_tree::ptree tree_container_policy_extensions_path;
    tree_container_policy_extensions_container.put_value("random");
    tree_container_policy_extensions_path.put_value("/random_path/");
    tree_container_policy_extension.add_child("container", tree_container_policy_extensions_container);
    tree_container_policy_extension.add_child("path", tree_container_policy_extensions_path);
    tree_container_policy_extensions.add_child("extension", tree_container_policy_extension);
    tree.add_child("container_policy_extensions", tree_container_policy_extensions);
    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Load policy element, which should should add the container and its path to policy_extension_paths_.
    its_policy_manager->load(its_element, not_lazy_load);

    // Test method
    ASSERT_EQ(its_policy_manager->get_policy_extension_path(its_client_host), "/etc/random_path/");
}

TEST(security_policy_manager_test, is_policy_removal_allowed) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Test method. Expect true because it will return the default option !check_whitelist_ which is false.
    ASSERT_TRUE(its_policy_manager->is_policy_removal_allowed(uid));

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_check_whitelists;
    boost::property_tree::ptree tree_security_update_whitelist;
    boost::property_tree::ptree tree_whitelists_any_interval;

    // Change check_whitelist_ to true, so we get false if we get the previous return.
    tree_check_whitelists.put_value("true");
    tree_security_update_whitelist.add_child("check-whitelist", tree_check_whitelists);

    // Set any interval so we should get true if the uid is contained within the min and max.
    tree_whitelists_any_interval.put_value("any");
    tree_security_update_whitelist.add_child("uids", tree_whitelists_any_interval);
    tree.add_child("security-update-whitelist", tree_security_update_whitelist);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Load policy element, which should should add the container and its path to policy_extension_paths_.
    its_policy_manager->load(its_element, not_lazy_load);

    // Test method. Expect true. Since we set up an interval, if uid is between 0 and max uint32_t we should get true.
    ASSERT_TRUE(its_policy_manager->is_policy_removal_allowed(uid));
}

TEST(security_policy_manager_test, is_policy_update_allowed) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Create a policy
    // Policy shared pointer to be used for test set up.
    std::shared_ptr<vsomeip_v3::policy> its_policy(new vsomeip_v3::policy());

    // Create an array of policy
    vsomeip_v3::byte_t byte_array_[array_size]{
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

    const vsomeip_v3::byte_t *data_ptr_ = byte_array_;
    std::uint32_t data_size_ = array_size;

    // Filling in the policy.
    ASSERT_TRUE(its_policy->deserialize(data_ptr_, data_size_));

    // Test method. Expect true because it will return the default option !check_whitelist_ which is false.
    ASSERT_TRUE(its_policy_manager->is_policy_update_allowed(uid, its_policy));

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_check_whitelists;
    boost::property_tree::ptree tree_security_update_whitelist;
    boost::property_tree::ptree tree_whitelists_any_interval;

    // Change check_whitelist_ to true, so we get false if we get the previous return.
    tree_check_whitelists.put_value("true");
    tree_security_update_whitelist.add_child("check-whitelist", tree_check_whitelists);

    // Set any interval for uid and services so we should get true if the uid is contained within the min and max.
    tree_whitelists_any_interval.put_value("any");
    tree_security_update_whitelist.add_child("uids", tree_whitelists_any_interval);
    tree_whitelists_any_interval.put_value("any");
    tree_security_update_whitelist.add_child("services", tree_whitelists_any_interval);
    tree.add_child("security-update-whitelist", tree_security_update_whitelist);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Load policy element, which should should add the container and its path to policy_extension_paths_.
    its_policy_manager->load(its_element, not_lazy_load);

    // Test method. Expect true because uid and service matched.
    ASSERT_TRUE(its_policy_manager->is_policy_update_allowed(uid, its_policy));
}

TEST(security_policy_manager_test, get_security_config_folder) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Create a string stream to build the full path to the security config folder.
    std::stringstream final_path;

    // Create a string to the path to the current unit test folder.
    const std::string folder_path = UNIT_TEST_BUILD_DIR_PATH "/security_policy_manager_impl_tests";

    const std::string fake_path = "fake_path";

    // Test method, since the folder does not exist, expect a default return.
    ASSERT_EQ(its_policy_manager->get_security_config_folder(fake_path), "");

    // Complete the path, adding the uid and gid.
#ifdef _WIN32
    final_path << folder_path << "/0_0";
#else
    final_path << folder_path << "/" << getuid() << "_" << getgid();
#endif

    // Convert stringstream to char*
    const std::string tmp = final_path.str();
    const char* final_path_string = tmp.c_str();

    boost::system::error_code ec;
    // Create the directory.
    boost::filesystem::create_directory(final_path_string, ec);

    // Test method. Since the folder now exists we expect to get the path returned.
    ASSERT_EQ(its_policy_manager->get_security_config_folder(folder_path), final_path_string);

    // Clean up, remove directory.
    boost::filesystem::remove_all(final_path_string, ec);
}

TEST(security_policy_manager_test, is_policy_extension_loaded) {
    // Test pointer.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_policy_manager(new vsomeip_v3::policy_manager_impl());

    // Client name.
    const std::string client_name("random");

    // Test method. No path has yet to be added.
    ASSERT_EQ(its_policy_manager->is_policy_extension_loaded(client_name),
        vsomeip_v3::policy_manager_impl::policy_loaded_e::POLICY_PATH_INEXISTENT);

    // Create a string stream to build the relative path to the security config folder.
    std::stringstream final_path;

    // Create a secondary path which will be full path.
    std::stringstream final_path2;

    // Create a string of the build path to the current test.
    const std::string folder_path = "build/test/unit_tests/security_policy_manager_impl_tests";

    // Complete the path, adding the uid and gid.
#ifdef _WIN32
    final_path << folder_path << "/0_0";
#else
    final_path << folder_path << "/" << getuid() << "_" << getgid();
#endif

    // Add a way to move out of the /etc folder we will be forced in.
    final_path2 << "../.." << UNIT_TEST_BUILD_DIR_PATH << "/security_policy_manager_impl_tests";

    // Convert stringstream to char*
    const std::string tmp = final_path.str();
    const char* final_path_string = tmp.c_str();
    const std::string tmp2 = final_path2.str();
    const char* final_path_string2 = tmp2.c_str();

    boost::system::error_code ec;
    // Create the directory.
    boost::filesystem::create_directory(final_path_string, ec);

    // Create a policy element setting check_credentials to true.
    const std::string element_name = "random";
    boost::property_tree::ptree tree;
    boost::property_tree::ptree tree_security;
    boost::property_tree::ptree tree_check_credentials;
    boost::property_tree::ptree tree_container_policy_extensions;
    boost::property_tree::ptree tree_container_policy_extension;
    boost::property_tree::ptree tree_container_policy_extensions_container;
    boost::property_tree::ptree tree_container_policy_extensions_path;
    tree_container_policy_extensions_container.put_value("random");
    tree_container_policy_extensions_path.put_value(final_path_string2);
    tree_container_policy_extension.add_child("container", tree_container_policy_extensions_container);
    tree_container_policy_extension.add_child("path", tree_container_policy_extensions_path);
    tree_container_policy_extensions.add_child("extension", tree_container_policy_extension);
    tree.add_child("container_policy_extensions", tree_container_policy_extensions);
    tree_check_credentials.put_value("true");
    tree_security.add_child("check_credentials", tree_check_credentials);
    tree.add_child("security", tree_security);

    const boost::property_tree::ptree tree_ptr = tree;
    vsomeip_v3::configuration_element its_element(element_name, tree_ptr);

    // Need to load a policy extension.
    its_policy_manager->load(its_element, not_lazy_load);

    // Test method. Expect an inexistent return because the set_is_plocity_extension_loaded method hasn't be called.
    ASSERT_EQ(its_policy_manager->is_policy_extension_loaded(client_name),
        vsomeip_v3::policy_manager_impl::policy_loaded_e::POLICY_PATH_INEXISTENT);

    // Associated test method. True for loaded.
    its_policy_manager->set_is_policy_extension_loaded(client_name, true);

    // Test method. Expect an outcome different from the last since we called the method.
    ASSERT_NE(its_policy_manager->is_policy_extension_loaded(client_name),
        vsomeip_v3::policy_manager_impl::policy_loaded_e::POLICY_PATH_INEXISTENT);

    // Test method. Since we used true for loaded in the set method we expect found and loaded return.
    ASSERT_EQ(its_policy_manager->is_policy_extension_loaded(client_name),
        vsomeip_v3::policy_manager_impl::policy_loaded_e::POLICY_PATH_FOUND_AND_LOADED);

    // Associated test method. False for loaded.
    its_policy_manager->set_is_policy_extension_loaded(client_name, false);

    // Test method. We now expect found but not loaded return.
    ASSERT_EQ(its_policy_manager->is_policy_extension_loaded(client_name),
        vsomeip_v3::policy_manager_impl::policy_loaded_e::POLICY_PATH_FOUND_AND_NOT_LOADED);

    // Clean up, remove directory.
    boost::filesystem::remove_all(final_path_string, ec);
}
