// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <common/utility.hpp>

namespace {
vsomeip_v3::uid_t invalid_uid = 1;
vsomeip_v3::uid_t valid_uid = 4002200;
vsomeip_v3::gid_t invalid_gid = 1;
vsomeip_v3::gid_t valid_gid = 4003014;
}

TEST(remove_security_policy_test, check_no_policies_loaded)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // no policies loaded -> remove_security_policy will return true independent of the uid or gid
    EXPECT_FALSE(security->remove_security_policy(valid_uid, valid_gid));
    EXPECT_FALSE(security->remove_security_policy(invalid_uid, valid_gid));
    EXPECT_FALSE(security->remove_security_policy(valid_uid, invalid_gid));
    EXPECT_FALSE(security->remove_security_policy(invalid_uid, invalid_gid));
}

TEST(remove_security_policy_test, check_policies_loaded)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip),
                       policy_elements, its_failed);

    for (const auto &e : policy_elements)
        security->load(e, false);

    // check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    // the check_credentials_ and the policy_enabled_ variables should be set to true
    ASSERT_FALSE(security->is_audit());
    ASSERT_TRUE(security->is_enabled());

    // invalid uid and gid -> remove_security_policy must return false
    EXPECT_FALSE(security->remove_security_policy(invalid_uid, invalid_gid));

    // invalid uid and valid gid -> remove_security_policy must return false
    EXPECT_FALSE(security->remove_security_policy(invalid_uid, valid_gid));

    // valid uid and invalid gid -> remove_security_policy must return false
    EXPECT_FALSE(security->remove_security_policy(valid_uid, invalid_gid));

    // valid uid and gid -> remove_security_policy must return true
    EXPECT_TRUE(security->remove_security_policy(valid_uid, valid_gid));
}
