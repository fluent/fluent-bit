// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <memory>

#include <common/utility.hpp>

namespace
{
    std::string configuration_file{"/vsomeip/0_0/vsomeip_security.json"};
}

TEST(load, No_element)
{
    // Test object path
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    // Set element
    std::vector<vsomeip_v3::configuration_element> empty_element = {}; // elements
    std::vector<vsomeip_v3::configuration_element> full_element = {};

    // Check element and full element size init =zero
    ASSERT_TRUE(empty_element.size() == 0) << " Initial element size is not zero";
    ASSERT_TRUE(full_element.size() == 0) << " Initial full element size is not zero";

    // After load try again and check size
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(
                           utility::get_policies_path(), dir_skip),
                       full_element, its_failed); // check if this is load without for cicle

    // Load each e into policy_elements
    for (const auto &e : full_element)
    {
        its_manager->load(e, false); // for each e in policy_elements vector load e
    };

    // Check size of full_element after load >0
    ASSERT_TRUE(full_element.size() > 0) << "Full element size is zero after load, should be >0 since policy was loaded";

    // Compare full element greater than element
    ASSERT_GT(full_element.size(), empty_element.size()) << "Full element is not greater than unit element";
}

TEST(load, _lazy_load)
{
    // Test object path
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    // Set element and lazy load
    std::vector<vsomeip_v3::configuration_element> element = {};
    const bool lazy_load = true;

    // Load
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(
                           utility::get_policies_path(), dir_skip),
                       element, its_failed);

    // Apply load function for each e into element and check if lazy load=true for each e loaded
    for (const auto &e : element)
    {
        its_manager->load(e, lazy_load);
        EXPECT_EQ(lazy_load, true) << "Lazy load not equal true";
    };

    // Test first element without for cycle
    const vsomeip_v3::configuration_element &e = element.at(0);
    its_manager->load(e, lazy_load);
    EXPECT_EQ(lazy_load, true) << "Lazy load not equal true";
}

TEST(load, policy_enabled_and_check_credentials)
{
    // Test object path
    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    // Set element and lazy load
    std::vector<vsomeip_v3::configuration_element> element = {};

    // Check values for policy enabled and check_credentials before load policy
    // No policies loaded -> check credentials will return false. policy_enabled is private so needs to be check like this
    ASSERT_TRUE(its_manager->is_audit()) << "policies were loaded. policy_enable should be true";
    ASSERT_FALSE(its_manager->is_enabled()) << "policies were loaded. check_credentials should be false";

    // Load full
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(
                           utility::get_policies_path(), dir_skip),
                       element, its_failed);

    // Load each e into policy_elements
    for (const auto &e : element)
    {
        its_manager->load(e, false); // for each e in policy_elements vector load e
    };

    // Check policies loaded after
    ASSERT_FALSE(its_manager->is_audit()) << "policies were loaded. policy_enable should be false";
    ASSERT_TRUE(its_manager->is_enabled()) << "policies were loaded. check_credentials should be true";
}
