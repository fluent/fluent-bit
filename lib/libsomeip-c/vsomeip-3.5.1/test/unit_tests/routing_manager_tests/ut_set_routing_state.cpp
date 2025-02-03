// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "routing_manager_ut_setup.hpp"

using ::testing::ReturnRef;
using ::testing::Return;
using ::testing::AtLeast;
using ::testing::_;

namespace {
    vsomeip_v3::service_t service_ = 0x1234;
    vsomeip_v3::instance_t instance_ = 0x5678;
    vsomeip_v3::service_t service2_ = 0x123;
    vsomeip_v3::instance_t instance2_ = 0x567;
    vsomeip_v3::major_version_t major_version_ = 1;
    vsomeip_v3::minor_version_t minor_version_ = 1;
    vsomeip_v3::ttl_t ttl_ = 3;
    boost::asio::detail::array<unsigned char, 4> ip_bytes_= { 127, 0, 0, 1 };
    boost::asio::ip::address_v4 ip_address_(ip_bytes_);
    boost::asio::detail::array<unsigned char, 4> ip_bytes_remote_= { 0xDE, 0xAD, 0xBE, 0xEF };
    boost::asio::ip::address_v4 ip_address_remote_(ip_bytes_remote_);
    std::uint16_t port_reliable = 3506;
    std::uint16_t port_unreliable = 3507;
}

TEST_F(routing_manager_ut_setup, DISABLED_set_routing_state_RS_SUSPENDED) {

    // Called on mock_host_ as a result of routing_manager_impl::del_routing_info being called within the logic tree
    EXPECT_CALL(mock_host_, on_availability(_,_,_,_,_)).Times(AtLeast(1));

    // Adding a service using add_routing_info this is a local service probably need to add remotes for this test
    its_manager->add_routing_info(service_, instance_, major_version_, minor_version_,
        ttl_, ip_address_, port_reliable, ip_address_, port_unreliable);

    // remote for on avail to be called as part of the del_routing_info call
    its_manager->add_routing_info(service2_, instance2_, major_version_, minor_version_,
        ttl_, ip_address_remote_, port_reliable, ip_address_remote_, port_unreliable);

    // Check it was added
    auto service_list = its_manager->get_offered_services();
    ASSERT_TRUE(service_list.size() > 0);

    // Call test method with test input.
    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_SUSPENDED);

    // Assert routing state, is equal to tested state.
    ASSERT_EQ(its_manager->get_routing_state(), vsomeip_v3::routing_state_e::RS_SUSPENDED);
}

TEST_F(routing_manager_ut_setup, DISABLED_set_routing_state_RS_RUNNING) {

    // Adding a service using add_routing_info
    its_manager->add_routing_info(service_, instance_, major_version_, minor_version_,
        ttl_, ip_address_, port_reliable, ip_address_, port_unreliable);

    // Check it was added
    auto service_list = its_manager->get_offered_services();
    ASSERT_TRUE(service_list.size() > 0);

    // RS_RUNNING is the default value so set RS_SUSPENDED back to RS_RUNNING
    // This is needed because the method exits right away if there is no state change.
    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_SUSPENDED);
    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_RUNNING);

    // Assert routing state, is equal to tested state.
    ASSERT_EQ(its_manager->get_routing_state(), vsomeip_v3::routing_state_e::RS_RUNNING);

    for (const auto &its_service : its_manager->get_offered_services()) {
        for (const auto &its_instance : its_service.second) {
            ASSERT_EQ(its_instance.second->get_ttl(), DEFAULT_TTL);
            ASSERT_FALSE(its_instance.second->is_in_mainphase());
        }
    }
}

TEST_F(routing_manager_ut_setup, DISABLED_set_routing_state_RS_RESUMED) {

    // Adding a service using add_routing_info
    its_manager->add_routing_info(service_, instance_, major_version_, minor_version_,
        ttl_, ip_address_, port_reliable, ip_address_, port_unreliable);

    // Check it was added
    auto service_list = its_manager->get_offered_services();
    ASSERT_TRUE(service_list.size() > 0);

    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_RESUMED);

    // Assert routing state, is equal to tested state.
    ASSERT_EQ(its_manager->get_routing_state(), vsomeip_v3::routing_state_e::RS_RESUMED);

    for (const auto &its_service : its_manager->get_offered_services()) {
        for (const auto &its_instance : its_service.second) {
            ASSERT_EQ(its_instance.second->get_ttl(), DEFAULT_TTL);
            ASSERT_FALSE(its_instance.second->is_in_mainphase());
        }
    }
}

TEST_F(routing_manager_ut_setup, DISABLED_set_routing_state_RS_SHUTDOWN) {

    // Call test method with test input.
    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_SHUTDOWN);

    // Assert routing state, is equal to tested state.
    ASSERT_EQ(its_manager->get_routing_state(), vsomeip_v3::routing_state_e::RS_SHUTDOWN);
}

TEST_F(routing_manager_ut_setup, DISABLED_set_routing_state_RS_DIAGNOSIS) {

    // Adding a service using add_routing_info
    its_manager->add_routing_info(service_, instance_, major_version_, minor_version_,
        ttl_, ip_address_, port_reliable, ip_address_, port_unreliable);

    // Check it was added
    auto service_list = its_manager->get_offered_services();
    ASSERT_TRUE(service_list.size() > 0);

    // Call test method with test input.
    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_DIAGNOSIS);

    // Assert routing state, is equal to tested state.
    ASSERT_EQ(its_manager->get_routing_state(), vsomeip_v3::routing_state_e::RS_DIAGNOSIS);

    // Check ttl was set to 0 done in discovery_->stop_offer_service
    for (const auto &its_service : its_manager->get_offered_services()) {
        for (const auto &its_instance : its_service.second) {
            ASSERT_EQ(its_instance.second->get_ttl(), 0);
        }
    }
}

TEST_F(routing_manager_ut_setup, DISABLED_set_routing_state_RS_UNKNOWN) {

    // RS_RUNNING is the default value so set RS_UNKOWN
    its_manager->set_routing_state(vsomeip_v3::routing_state_e::RS_UNKNOWN);

    // Assert routing state, is equal to tested state.
    ASSERT_EQ(its_manager->get_routing_state(), vsomeip_v3::routing_state_e::RS_UNKNOWN);
}
