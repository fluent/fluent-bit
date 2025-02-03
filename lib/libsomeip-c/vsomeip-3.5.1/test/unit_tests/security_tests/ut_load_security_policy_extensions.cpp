// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <common/utility.hpp>
#include <gtest/gtest.h>
#include <memory>

// create valid and invalid user credentials
namespace
{
    std::string configuration_file{
        "/vsomeip/vsomeip_policy_extensions.json"}; // set configuration file policy

} // namespace

TEST(load_security_policy_extensions, no_configuration_element)
{
    // Test object path.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
        new vsomeip_v3::policy_manager_impl};

    // Set element.
    std::vector<vsomeip_v3::configuration_element> element;
    std::vector<vsomeip_v3::configuration_element> full_element;

    // Save init size values.
    auto element_size = element.size();
    auto full_element_size = full_element.size();

    // Check element and full element size init =zero.
    ASSERT_TRUE(element.size() == 0) << " Initial element size is not zero";

    // After load try again and check size.
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(
        utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip),
        full_element, its_failed);

    // Load each e into policy_elements.
    for (const auto &e : full_element)
    {
        security->load(e, false);
    }

    ASSERT_EQ(element_size, full_element_size)
        << "Policy element before load is not zero. Size = " << element_size
        << " And size after load = " << full_element_size;

    // Check size of full_element after load >0
    ASSERT_TRUE(full_element.size() > 0)
        << "Full element size is zero after load, should be >0 since policy was "
           "loaded";
}

TEST(load_security_policy_extensions, configuration_element)
{
    // Test object path.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
        new vsomeip_v3::policy_manager_impl};

    // Set element.
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<vsomeip_v3::configuration_element> element;

    // Force load of policies.
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(
        utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip),
        policy_elements, its_failed);

    // Load each e into policy_elements.
    for (const auto &e : policy_elements)
    {
        security->load(e, false);
    }

    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_GT(policy_elements.size(), element.size()) << "Policies did not load";
}

TEST(load_security_policy_extensions, is_policy_extension_loaded)
{
    // Test object path.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
        new vsomeip_v3::policy_manager_impl};

    // Set element.
    std::vector<vsomeip_v3::configuration_element> policy_elements;

    // Force Load of policies.
    std::set<std::string> its_failed;
    std::set<std::string> input{utility::get_policies_path() +
                                configuration_file};
    utility::read_data(input, policy_elements, its_failed);

    // Load policies.
    security->load(policy_elements.at(0));

    // Check JSON container string.
    std::string policy_extension_container{"android-rse"};

    // Set extension loaded.
    bool loaded_extension = true;
    security->set_is_policy_extension_loaded(policy_extension_container, loaded_extension);

    // Print path for "android-rse".
    std::cout << "Policy Extension Path: " << security->get_policy_extension_path(policy_extension_container) << std::endl;

    // Check if policy extension is loaded and path found.
    ASSERT_EQ(security->is_policy_extension_loaded(policy_extension_container), vsomeip_v3::policy_manager_impl::policy_loaded_e::
                                                                                    POLICY_PATH_FOUND_AND_LOADED);
}

TEST(load_security_policy_extensions, is_policy_extension_NOT_loaded)
{
    // Test object path.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
        new vsomeip_v3::policy_manager_impl};

    // Set element.
    std::vector<vsomeip_v3::configuration_element> policy_elements;

    // Force load of policies and read data.
    std::set<std::string> its_failed;
    std::set<std::string> input{utility::get_policies_path() +
                                configuration_file};
    utility::read_data(input, policy_elements, its_failed);

    // Load Policies.
    security->load(policy_elements.at(0));

    // Check JSON container string.
    std::string policy_extension_container{"android-rse"};

    // Set extension as not loaded.
    bool loaded_extension = false;
    security->set_is_policy_extension_loaded(policy_extension_container, loaded_extension);

    // Print path for "android-rse".
    std::cout << "Policy Extension Path: " << security->get_policy_extension_path(policy_extension_container) << std::endl;

    // Check if policy extension is loaded and path found.
    ASSERT_EQ(security->is_policy_extension_loaded(policy_extension_container), vsomeip_v3::policy_manager_impl::policy_loaded_e::
                                                                                    POLICY_PATH_FOUND_AND_NOT_LOADED);
}

TEST(load_security_policy_extensions, is_policy_extension_NOT_found)
{
    // Test object path.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
        new vsomeip_v3::policy_manager_impl};

    // Check path not found and extension not loaded.
    ASSERT_EQ(security->is_policy_extension_loaded(""), vsomeip_v3::policy_manager_impl::policy_loaded_e::POLICY_PATH_INEXISTENT);
}
