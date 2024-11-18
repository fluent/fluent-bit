// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include "gtest/gtest.h"
#include <common/utility.hpp>

namespace {
    vsomeip_v3::uid_t uid_1 = 4003031;
    vsomeip_v3::gid_t gid_1 = 4003031;
    vsomeip_sec_ip_addr_t host_address = 0;
    vsomeip_v3::service_t  service_1 = 0xf913;

    vsomeip_v3::service_t  service_2 = 0x41;    // service not defined in policies

    vsomeip_v3::instance_t instance = 0x03;
    vsomeip_v3::instance_t instance_2 = 0x04;
    vsomeip_v3::method_t method = 0x04;
    vsomeip_v3::method_t method_2 = 0x05;

    vsomeip_v3::gid_t invalid_uid = 1;
    vsomeip_v3::gid_t invalid_gid = 1;
    vsomeip_v3::uid_t ANY_UID = 0xFFFFFFFF;
    vsomeip_v3::gid_t ANY_GID = 0xFFFFFFFF;

    vsomeip_v3::gid_t deny_uid  = 9999;
    vsomeip_v3::gid_t deny_gid  = 9999;
    vsomeip_v3::service_t deny_service = 0x40;
}

TEST(is_client_allowed_test, check_no_policies_loaded) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    //no policies loaded -> is_client_allowed must return true
    ASSERT_FALSE(its_manager->is_enabled());

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_invalid, service_1, instance, method));
}

TEST(is_client_allowed_test, check_policies_loaded) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    //check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    for (const auto& e : policy_elements) {
    	its_manager->load(e, false);
    }

    // check if the policies are loaded and check_credentials_ variable are true
    ASSERT_TRUE(its_manager->is_enabled());
    ASSERT_FALSE(its_manager->is_audit());

    // create security clients
    vsomeip_sec_client_t its_sec_client = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_uid = utility::create_uds_client(invalid_uid, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_gid = utility::create_uds_client(uid_1, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_any = utility::create_uds_client(ANY_UID, ANY_GID, host_address);
    vsomeip_sec_client_t its_sec_client_deny = utility::create_uds_client(deny_uid, deny_gid, host_address);

    //valid credential for valid service / istance / method
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance, method));

    // test is_client_allowed_cache_, request with the same credentials and service / instance / method
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance, method));

    // test is_client_allowed_cache_, request with the same credentials and service but with a different instance or method
    // is_client_allowed return true because it's define ANY_INSTANCE and ANY_METHOD in the policy
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance_2, method));
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance, method_2));

    //invalid credential for the service / istance / method
    EXPECT_FALSE(its_manager->is_client_allowed(&its_sec_client_invalid_uid, service_1, instance, method));
    EXPECT_FALSE(its_manager->is_client_allowed(&its_sec_client_invalid_gid, service_1, instance, method));

    //ANY_UID and ANY_GID
    EXPECT_FALSE(its_manager->is_client_allowed(&its_sec_client_any, service_1, instance, method));

    // test deny client
    // deny client with credentials for the service
    EXPECT_FALSE(its_manager->is_client_allowed(&its_sec_client_deny, deny_service, instance, method));
    // credencials exists in deny policy, but not for that service
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_deny, service_2, instance, method));
}


// is_client_allowed with policies loaded but in audit mode
// vsomeip's security implementation can be put in a so called 'Audit Mode' where
// all security violations will be logged but allowed.
// To activate the 'Audit Mode' the 'security' object has to be included in the
// json file but the 'check_credentials' switch has to be set to false.
 TEST(is_client_allowed_test, check_policies_loaded_in_audit_mode) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    //check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    utility::force_check_credentials(policy_elements, "false");

    for (const auto& e : policy_elements) {
    	its_manager->load(e, false);
    }

    // check if the policies are loaded and check_credentials_ variable are false
    ASSERT_TRUE(its_manager->is_enabled());
    ASSERT_TRUE(its_manager->is_audit());

    // create security clients
    vsomeip_sec_client_t its_sec_client = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_uid = utility::create_uds_client(invalid_uid, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_gid = utility::create_uds_client(uid_1, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_any = utility::create_uds_client(ANY_UID, ANY_GID, host_address);
    vsomeip_sec_client_t its_sec_client_deny = utility::create_uds_client(deny_uid, deny_gid, host_address);

    // is expected is_client_allowed method always returns true
    // valid credential for valid service / istance / method
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance, method));

    // test is_client_allowed_cache_, request with the same credentials and service / instance / method
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance, method));

    // test is_client_allowed_cache_, request with the same credentials and service but with a different instance or method
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance_2, method));
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client, service_1, instance, method_2));

    // invalid credential for the service / istance / method
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_invalid_uid, service_1, instance, method));
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_invalid_gid, service_1, instance, method));

    // ANY_UID and ANY_GID
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_any, service_1, instance, method));

    // test deny client
    // deny client with credentials for the service
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_deny, deny_service, instance, method));
    // credencials exists in deny policy, but not for that service
    EXPECT_TRUE(its_manager->is_client_allowed(&its_sec_client_deny, service_2, instance, method));
}
