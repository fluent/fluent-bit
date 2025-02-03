// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace {
std::string configuration_file { "/vsomeip/0_0/vsomeip_security.json" };
vsomeip_v3::uid_t valid_uid = 4002200;
vsomeip_v3::gid_t valid_gid = 4003014;
}

// Since this set of tests check a private method, there is the need to indirectly change the
// parameters used by load_policies, and check its changes using other methods.
// The remove_security_policy method checks if there is any loaded policy.
// The is_audit method checks the check_credentials value.
// No test was created for allow_remote_clients because it was inacessible.

TEST(load_policies, any_policies_present)
{
    // LOADED POLICIES --------------------------------------------------------------------------//
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Check if the load worked.
    ASSERT_EQ(its_failed.size(), 0);

    // Using load function to indirectly call load_policies.
    security->load(policy_elements.at(0));

    // Check that the policies were loaded from the file by trying to remove one of the loaded
    // policies.
    // If the policy is present, remove_security_policy returns true.
    ASSERT_TRUE(security->remove_security_policy(valid_uid,valid_gid))
            << "Trying to remove a policy that is supposed to exist, but doesn't";

    // POLICIES NOT LOADED -----------------------------------------------------------------------//
    // Remove all the policies from the file.
    policy_elements.at(0).tree_.get_child("security").erase("policies");

    // Using load function to indirectly call load_policies.
    security->load(policy_elements.at(0));

    // Check that no policies were loaded.
    ASSERT_FALSE(security->remove_security_policy(valid_uid,valid_gid))
            << "Trying to remove a policy should not exist, but it exists";
}

TEST(load_policies, check_credentials)
{
    // CHECK CREDENTIALS NOT SET -----------------------------------------------------------------//
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies without the check credentials value set.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Check if the load worked.
    ASSERT_EQ(its_failed.size(), 0);

    security->load(policy_elements.at(0));

    // Check that the check_credentials value was not set, using the is_audit method.
    ASSERT_TRUE(security->is_audit())
            << "Check credentials value should be false when no value is loaded";

    // CHECK CREDENTIALS SET TRUE ----------------------------------------------------------------//

    // Load the check credentials value as false.
    bool check_credentials_value {true};
    policy_elements.at(0).tree_.add<bool>("security.check_credentials", check_credentials_value);
    security->load(policy_elements.at(0));

    // Check that the check_credentials flag was not set internally, using the is_audit method.
    ASSERT_FALSE(security->is_audit())
            << "Check credentials flag should be true when the check_credential value is loaded as"
                "true";

    // CHECK CREDENTIALS SET FALSE ---------------------------------------------------------------//

    // Load the check credentials value as false.
    check_credentials_value = false;
    policy_elements.at(0).tree_.put<bool>("security.check_credentials", check_credentials_value);
    security->load(policy_elements.at(0));

    // Check that the check_credentials flag was set false, using the is_audit method.
    ASSERT_TRUE(security->is_audit())
            << "Check credentials flag should be false when the check_credential value is loaded as"
                "false";
}
