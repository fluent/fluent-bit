// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef ROUTING_MANAGER_UT_SETUP_HPP
#define ROUTING_MANAGER_UT_SETUP_HPP

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <common/utility.hpp>

#include "mocks/mock_routing_manager_host.hpp"

class routing_manager_ut_setup : public testing::Test{
protected :
    mock_routing_manager_host mock_host_;
    vsomeip_v3::routing_manager_impl* its_manager;
    const std::string name_ = "RandomName";
    boost::asio::io_service io_;
    std::shared_ptr<vsomeip_v3::cfg::configuration_impl> configuration_ptr_;
    void SetUp() override;
    // Tears down the test fixture.
    void TearDown() override;
};

#endif // ROUTING_MANAGER_UT_SETUP_HPP
