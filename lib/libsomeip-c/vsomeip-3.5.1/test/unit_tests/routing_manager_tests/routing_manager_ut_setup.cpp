// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "routing_manager_ut_setup.hpp"

using ::testing::ReturnRef;
using ::testing::Return;

void routing_manager_ut_setup::SetUp() {
    configuration_ptr_ =
        std::make_shared<vsomeip_v3::cfg::configuration_impl>("routing_manager_ut_config.json");

    EXPECT_CALL(mock_host_, get_io()).WillRepeatedly(ReturnRef(io_));
    EXPECT_CALL(mock_host_, get_name()).WillRepeatedly(ReturnRef(name_));
    EXPECT_CALL(mock_host_, get_configuration()).WillRepeatedly(Return(configuration_ptr_));

    // Create a test routing manager impl, with mock_host for routing_manager_host.
    its_manager = new vsomeip_v3::routing_manager_impl(&mock_host_);

    its_manager->init();
}

void routing_manager_ut_setup::TearDown() {
    delete its_manager;
    configuration_ptr_.reset();
}
