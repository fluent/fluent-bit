// Copyright (C) 2014-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <thread>
#include <future>
#include <cstring>

#include <vsomeip/vsomeip.hpp>
#include "../../implementation/utility/include/utility.hpp"
#include "../../implementation/configuration/include/configuration.hpp"
#include "../../implementation/configuration/include/configuration_plugin.hpp"
#include "../../implementation/plugin/include/plugin_manager_impl.hpp"
#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

using namespace vsomeip;

static const std::string APPLICATION_NAME_ROUTING_MANAGER = "routingmanagerd";

static const std::string APPLICATION_NAME_NOT_PREDEFINED = "test-application-name";

vsomeip::client_t CLIENT_ID_ROUTING_MANAGER = 0xFFFF;

static const std::string APPLICATION_IN_NAME = "client_id_test_utility_service_in";
static vsomeip::client_t APPLICATION_IN_CLIENT_ID = 0xFFFF;

static const std::string APPLICATION_IN_NAME_TWO = "client_id_test_utility_service_in_two";
static vsomeip::client_t APPLICATION_IN_CLIENT_ID_TWO = 0xFFFF;

static const std::string APPLICATION_OUT_LOW_NAME = "client_id_test_utility_service_out_low";
static const vsomeip::client_t APPLICATION_OUT_LOW_CLIENT_ID = 0x5911;

static const std::string APPLICATION_OUT_HIGH_NAME = "client_id_test_utility_service_out_high";
static const vsomeip::client_t APPLICATION_OUT_HIGH_CLIENT_ID = 0x7411;

class client_id_utility_test: public ::testing::Test {
public:
    client_id_utility_test() :
            client_id_routing_manager_(0x0),
            diagnosis_(0x0),
            diagnosis_mask_(0xFF00),
            client_id_base_(0x0) {

        std::shared_ptr<vsomeip::configuration> its_configuration;
        auto its_plugin = vsomeip::plugin_manager::get()->get_plugin(
                vsomeip::plugin_type_e::CONFIGURATION_PLUGIN, VSOMEIP_CFG_LIBRARY);
        if (its_plugin) {
            auto its_config_plugin = std::dynamic_pointer_cast<vsomeip::configuration_plugin>(its_plugin);
            if (its_config_plugin) {
                configuration_ = its_config_plugin->get_configuration(APPLICATION_NAME_ROUTING_MANAGER, "");
            }
        }
    }
protected:
    virtual void SetUp() {
        ASSERT_TRUE(static_cast<bool>(configuration_));
        configuration_->load(APPLICATION_NAME_ROUTING_MANAGER);
        diagnosis_mask_ = configuration_->get_diagnosis_mask();
        diagnosis_ = configuration_->get_diagnosis_address();

        // calculate all client IDs based on mask
        client_id_base_ = static_cast<client_t>(diagnosis_ << 8);
        CLIENT_ID_ROUTING_MANAGER =
                static_cast<client_t>((configuration_->get_diagnosis_address()
                        << 8) & configuration_->get_diagnosis_mask());
        APPLICATION_IN_CLIENT_ID = static_cast<client_t>(client_id_base_ | 0x11);
        APPLICATION_IN_CLIENT_ID_TWO = static_cast<client_t>(client_id_base_ | 0x12);

        app_ = vsomeip::runtime::get()->create_application(APPLICATION_NAME_ROUTING_MANAGER);
        EXPECT_TRUE(app_->init());
        EXPECT_EQ(CLIENT_ID_ROUTING_MANAGER, app_->get_client());

        rm_impl_thread_ = std::thread([&](){
            app_->start();
        });
        // ensure clean preconditions
        utility::reset_client_ids(configuration_->get_network());

        // required as there are two static versions of the utility class in this
        // test, one in the test itself and one in libvsomeip...
        client_id_routing_manager_ = utility::request_client_id(
                configuration_, APPLICATION_NAME_ROUTING_MANAGER, static_cast<client_t>(
                        (configuration_->get_diagnosis_address() << 8)
                      & configuration_->get_diagnosis_mask()));
        EXPECT_EQ(CLIENT_ID_ROUTING_MANAGER, client_id_routing_manager_);
    }

    virtual void TearDown() {
        app_->stop();
        if (rm_impl_thread_.joinable()) {
            rm_impl_thread_.join();
        }
        app_.reset();
        utility::release_client_id(configuration_->get_network(), client_id_routing_manager_);
    }

protected:
    std::shared_ptr<configuration> configuration_;
    vsomeip::client_t client_id_routing_manager_;
    std::uint16_t diagnosis_;
    std::uint16_t diagnosis_mask_;
    client_t client_id_base_;
    std::shared_ptr<vsomeip::application> app_;
    std::thread rm_impl_thread_;
};

class app_wrapper : public vsomeip_utilities::base_logger {
public:
    app_wrapper(const std::string& _name) :
        vsomeip_utilities::base_logger("APPW", "APP WRAPPER"),
        app_(vsomeip::runtime::get()->create_application(_name)),
        client_(VSOMEIP_CLIENT_UNSET) {
        EXPECT_TRUE(app_->init());
        app_->register_state_handler(
                std::bind(&app_wrapper::on_state, this, std::placeholders::_1));
        app_thread_ = std::thread([&](){ app_->start(); });
    }

    ~app_wrapper() {
        app_->stop();
        if (app_thread_.joinable()) {
            app_thread_.join();
        }
        app_.reset();
    }

    void on_state(const vsomeip::state_type_e& _state) {
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            client_ = app_->get_client();
            registered_.set_value();
        }
    };

    client_t get_client() {
        if (std::future_status::timeout
                == registered_.get_future().wait_for(
                        std::chrono::seconds(11))) {
            ADD_FAILURE()<< __LINE__ << " application wasn't registered within time";
        }
        return client_;
    }

    std::shared_ptr<vsomeip::application> get_app() {
        return app_;
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    std::promise<void> registered_;
    std::thread app_thread_;
    std::atomic<vsomeip::client_t> client_;
};

TEST_F(client_id_utility_test, request_release_client_id) {
    app_wrapper app(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x1, app.get_client());
}

TEST_F(client_id_utility_test, request_client_id_twice) {
    app_wrapper app(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x1, app.get_client());

    app_wrapper app2(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x2, app2.get_client());
}

TEST_F(client_id_utility_test, ensure_sequential_ascending_client_id_allocation) {
    app_wrapper app(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x1, app.get_client());

    auto app2 = std::make_shared<app_wrapper>(APPLICATION_NAME_NOT_PREDEFINED);
    client_t app2_client = app2->get_client();
    EXPECT_EQ(client_id_base_ | 0x2, app2_client);

    app2.reset();

    auto app3 = std::make_shared<app_wrapper>(APPLICATION_NAME_NOT_PREDEFINED);
    client_t app3_client = app3->get_client();
    EXPECT_EQ(client_id_base_ | 0x3, app3_client);

    EXPECT_GT(app3_client, app2_client);

}

TEST_F(client_id_utility_test, ensure_preconfigured_client_ids_not_used_for_autoconfig)
{
    // request client ids until 10 over the preconfigured one
    const std::uint16_t limit =
            static_cast<std::uint16_t>((APPLICATION_IN_CLIENT_ID
                    & ~diagnosis_mask_) + std::uint16_t(10));

    std::vector<std::shared_ptr<app_wrapper>> its_apps;
    its_apps.reserve(limit);

    for (int i = 0; i < limit; i++ ) {
        its_apps.emplace_back(
                std::make_shared<app_wrapper>(APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i)));
    }
    for (const auto& a : its_apps) {
        EXPECT_NE(APPLICATION_IN_CLIENT_ID, a->get_client());
    }
    its_apps.clear();
}

TEST_F(client_id_utility_test,
        request_predefined_client_id_in_diagnosis_range) {
    auto app1 = std::make_shared<app_wrapper>(APPLICATION_IN_NAME);
    EXPECT_EQ(APPLICATION_IN_CLIENT_ID, app1->get_client());
}

TEST_F(client_id_utility_test,
        request_predefined_client_id_in_diagnosis_range_twice) {
    auto app1 = std::make_shared<app_wrapper>(APPLICATION_IN_NAME);
    EXPECT_EQ(APPLICATION_IN_CLIENT_ID, app1->get_client());

    // preconfigured is already taken -> autogenerated ID should be returned
    auto app2 = std::make_shared<app_wrapper>(APPLICATION_IN_NAME);
    EXPECT_EQ(client_id_base_ | 0x1, app2->get_client());
}

TEST_F(client_id_utility_test,
        request_predefined_client_id_outside_diagnosis_range_high) {
    auto app1 = std::make_shared<app_wrapper>(APPLICATION_OUT_HIGH_NAME);
    // we should get the client ID defined in the json file
    EXPECT_EQ(APPLICATION_OUT_HIGH_CLIENT_ID, app1->get_client());
}

TEST_F(client_id_utility_test,
        request_client_id_with_predefined_app_name_outside_diagnosis_range_high_multiple) {

    auto app1 = std::make_shared<app_wrapper>(APPLICATION_OUT_HIGH_NAME);
    // we should get the client ID defined in the json file
    EXPECT_EQ(APPLICATION_OUT_HIGH_CLIENT_ID, app1->get_client());

    // preconfigured is already taken -> autogenerated ID should be returned
    auto app2 = std::make_shared<app_wrapper>(APPLICATION_OUT_HIGH_NAME);
    EXPECT_EQ(client_id_base_ | 0x1, app2->get_client());

    auto app3 = std::make_shared<app_wrapper>(APPLICATION_OUT_HIGH_NAME);
    EXPECT_EQ(client_id_base_ | 0x2, app3->get_client());
}

TEST_F(client_id_utility_test,
        request_predefined_client_id_outside_diagnosis_range_low) {
    auto app1 = std::make_shared<app_wrapper>(APPLICATION_OUT_LOW_NAME);
    // we should get the client ID defined in the json file
    EXPECT_EQ(APPLICATION_OUT_LOW_CLIENT_ID, app1->get_client());
}

TEST_F(client_id_utility_test,
        request_predefined_client_id_outside_diagnosis_range_low_multiple) {
    auto app1 = std::make_shared<app_wrapper>(APPLICATION_OUT_LOW_NAME);
    // we should get the client ID defined in the json file
    EXPECT_EQ(APPLICATION_OUT_LOW_CLIENT_ID, app1->get_client());

    // preconfigured is already taken -> autogenerated ID should be returned
    auto app2 = std::make_shared<app_wrapper>(APPLICATION_OUT_LOW_NAME);
    EXPECT_EQ(client_id_base_ | 0x1, app2->get_client());

    auto app3 = std::make_shared<app_wrapper>(APPLICATION_OUT_LOW_NAME);
    EXPECT_EQ(client_id_base_ | 0x2, app3->get_client());
}

TEST_F(client_id_utility_test,
       ensure_preconfigured_client_ids_in_diagnosis_range_dont_influence_autoconfig_client_ids)
{
    auto app0 = std::make_shared<app_wrapper>(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x1, app0->get_client());

    auto app1 = std::make_shared<app_wrapper>(APPLICATION_IN_NAME);
    EXPECT_EQ(APPLICATION_IN_CLIENT_ID, app1->get_client());

    auto app2 = std::make_shared<app_wrapper>(APPLICATION_IN_NAME_TWO);
    EXPECT_EQ(APPLICATION_IN_CLIENT_ID_TWO, app2->get_client());

    auto app3 = std::make_shared<app_wrapper>(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x2, app3->get_client());

    auto app4 = std::make_shared<app_wrapper>(APPLICATION_NAME_NOT_PREDEFINED);
    EXPECT_EQ(client_id_base_ | 0x3, app4->get_client());
}

TEST_F(client_id_utility_test, exhaust_client_id_range_sequential) {
    std::vector<vsomeip::client_t> its_clients;
    std::uint16_t its_max_clients(0);
    for (int var = 0; var < __builtin_popcount(static_cast<std::uint16_t>(~diagnosis_mask_)); ++var) {
        its_max_clients = static_cast<std::uint16_t>(its_max_clients | (1 << var));
    }
    // -2 as two predefined client IDs are present in the json file which
    // aren't assigned via autoconfiguration
    const std::uint16_t max_allowed_clients = static_cast<std::uint16_t>(its_max_clients - 2u);

    // acquire maximum amount of client IDs
    for (int var = 0; var < 2; ++var) {
        for (std::uint16_t i = 0; i < max_allowed_clients; i++) {
            const vsomeip::client_t its_client =
                    vsomeip::utility::request_client_id(configuration_,
                            APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i),
                            VSOMEIP_CLIENT_UNSET);
            if (its_client != VSOMEIP_CLIENT_UNSET) {
                if (i > 0) {
                    EXPECT_LT(its_clients.back(), its_client);
                }
                its_clients.push_back(its_client);
            } else {
                ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                        << static_cast<std::uint32_t>(i);
            }
        }
        // check limit is reached
        EXPECT_EQ(VSOMEIP_CLIENT_UNSET, vsomeip::utility::request_client_id(
                        configuration_, APPLICATION_NAME_NOT_PREDEFINED + "max",
                        VSOMEIP_CLIENT_UNSET));
        for (const auto c : its_clients) {
            utility::release_client_id(configuration_->get_network(), c);
        }
    }
 }

TEST_F(client_id_utility_test, exhaust_client_id_range_fragmented) {
    std::vector<client_t> its_clients;

    // -2 as two predefined client IDs are present in the json file which
    // aren't assigned via autoconfiguration
    std::uint16_t its_max_clients(0);
    for (int var = 0; var < __builtin_popcount(static_cast<std::uint16_t>(~diagnosis_mask_)); ++var) {
        its_max_clients = static_cast<std::uint16_t>(its_max_clients | (1 << var));
    }
    const std::uint16_t max_allowed_clients = static_cast<std::uint16_t>(its_max_clients - 2u);

    for (int var = 0; var < 2; ++var) {
        // acquire maximum amount of client IDs
        for (std::uint16_t i = 0; i < max_allowed_clients; i++) {
            const vsomeip::client_t its_client =
                    vsomeip::utility::request_client_id(configuration_,
                            APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i),
                            VSOMEIP_CLIENT_UNSET);
            if (its_client != VSOMEIP_CLIENT_UNSET) {
                if ((var == 0 && i > 0) ||
                    (var == 1 && i > 1) // special case as in the 1st run the last assigned client ID was 63fe
                                        // due to the releases. In the 2nd run the first client ID therefore will be 63ff
                    ) {
                    EXPECT_LT(its_clients.back(), its_client);
                }
                its_clients.push_back(its_client);
            } else {
                ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                        << static_cast<std::uint32_t>(i);
            }
        }

        // check limit is reached
        EXPECT_EQ(VSOMEIP_CLIENT_UNSET, vsomeip::utility::request_client_id(
                        configuration_, APPLICATION_NAME_NOT_PREDEFINED + "max",
                        VSOMEIP_CLIENT_UNSET));

        // release every second requested client ID
        std::vector<client_t> its_released_client_ids;
        for (size_t i = 0; i < its_clients.size(); i++ ) {
            if (i % 2) {
                its_released_client_ids.push_back(its_clients[i]);
                utility::release_client_id(configuration_->get_network(), its_clients[i]);
            }
        }
        for (const client_t c : its_released_client_ids) {
            for (auto it = its_clients.begin(); it != its_clients.end(); ) {
                if (*it == c) {
                    it = its_clients.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // acquire client IDs up to the maximum allowed amount again
        for (std::uint16_t i = 0; i < its_released_client_ids.size(); i++) {
            const vsomeip::client_t its_client =
                    vsomeip::utility::request_client_id(configuration_,
                            APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i),
                            VSOMEIP_CLIENT_UNSET);
            if (its_client != VSOMEIP_CLIENT_UNSET) {
                if (i > 0) {
                    EXPECT_LT(its_clients.back(), its_client);
                }
                its_clients.push_back(its_client);
            } else {
                ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                        << static_cast<std::uint32_t>(i);
            }
        }

        // check limit is reached
        EXPECT_EQ(VSOMEIP_CLIENT_UNSET, vsomeip::utility::request_client_id(
                        configuration_, APPLICATION_NAME_NOT_PREDEFINED + "max2",
                        VSOMEIP_CLIENT_UNSET));

        // release all
        for (const auto c : its_clients) {
            utility::release_client_id(configuration_->get_network(), c);
        }
        its_clients.clear();
    }
}

/*
 * @test Check that the autoconfigured client IDs continue to increase even if
 * some client IDs at the beginning of the range are already released again
 */
TEST_F(client_id_utility_test, exhaust_client_id_range_fragmented_extended) {
    std::vector<client_t> its_client_ids;

    // -1 for the routing manager, -2 as two predefined client IDs are present
    // in the json file which aren't assigned via autoconfiguration
    std::uint16_t its_max_clients(0);
    for (int var = 0; var < __builtin_popcount(static_cast<std::uint16_t>(~diagnosis_mask_)); ++var) {
        its_max_clients = static_cast<std::uint16_t>(its_max_clients | (1 << var));
    }
    const std::uint16_t its_diagnosis_mask = configuration_->get_diagnosis_mask();
    const std::uint16_t its_client_mask = static_cast<std::uint16_t>(~its_diagnosis_mask);
    const client_t its_masked_diagnosis_address = static_cast<client_t>(
            (configuration_->get_diagnosis_address() << 8) & its_diagnosis_mask);
    const client_t its_biggest_client = its_masked_diagnosis_address | its_client_mask;

    const std::uint16_t max_possible_clients = its_max_clients;
    const std::uint16_t intermediate_release = 3;
    const std::uint16_t max_allowed_clients = static_cast<std::uint16_t>(max_possible_clients - 2u);

    // acquire (almost) maximum amount of client IDs
    for (std::uint16_t i = 0; i < max_allowed_clients - intermediate_release; i++) {
        client_t its_client_id = utility::request_client_id(configuration_,
                APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i),
                VSOMEIP_CLIENT_UNSET);
        EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
        if (its_client_id != VSOMEIP_CLIENT_UNSET) {
            if (i > 0) {
                EXPECT_LT(its_client_ids.back(), its_client_id);
            }
            its_client_ids.push_back(its_client_id);
        } else {
            ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                    << static_cast<std::uint32_t>(i);
        }
    }

    // release the first intermediate_release client IDs again
    std::vector<client_t> its_intermediate_released_client_ids;
    for (size_t i = 0; i < intermediate_release; i++ ) {
        its_intermediate_released_client_ids.push_back(its_client_ids[i]);
        utility::release_client_id(configuration_->get_network(), its_client_ids[i]);
        its_client_ids.erase(its_client_ids.begin() + i);
    }

    // acquire some more client IDs, these should be bigger than the already acquired
    for (std::uint16_t i = 0; i < intermediate_release; i++) {
        client_t its_client_id = utility::request_client_id(configuration_,
                APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i)
                        + "intermediate",
                VSOMEIP_CLIENT_UNSET);
        EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
        if (its_client_id != VSOMEIP_CLIENT_UNSET) {
            EXPECT_LT(its_client_ids.back(), its_client_id);
            its_client_ids.push_back(its_client_id);
        } else {
            ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                    << static_cast<std::uint32_t>(i);
        }
    }

    // check correct wrap around of client IDs
    for (std::uint16_t i = 0; i < intermediate_release; i++) {
        client_t its_client_id = utility::request_client_id(configuration_,
                APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i),
                VSOMEIP_CLIENT_UNSET);
        EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
        if (its_client_id != VSOMEIP_CLIENT_UNSET) {
            if (i == 0) {
                EXPECT_GT(its_client_ids.back(), its_client_id);
            } else {
                EXPECT_LT(its_client_ids.back(), its_client_id);
            }
            its_client_ids.push_back(its_client_id);
        } else {
            ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                    << static_cast<std::uint32_t>(i);
        }
    }

    // check limit is reached
    client_t its_illegal_client_id = utility::request_client_id(configuration_,
            APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
    EXPECT_EQ(VSOMEIP_CLIENT_UNSET, its_illegal_client_id);

    // release every second requested client ID
    std::vector<client_t> its_released_client_ids;
    for (size_t i = 0; i < its_client_ids.size(); i++ ) {
        if (i % 2) {
            its_released_client_ids.push_back(its_client_ids[i]);
            utility::release_client_id(configuration_->get_network(), its_client_ids[i]);
        }
    }
    for (const client_t c : its_released_client_ids) {
        for (auto it = its_client_ids.begin(); it != its_client_ids.end(); ) {
            if (*it == c) {
                it = its_client_ids.erase(it);
            } else {
                ++it;
            }
        }
    }

    // acquire client IDs up to the maximum allowed amount again
    for (std::uint16_t i = 0; i < its_released_client_ids.size(); i++) {
        client_t its_client_id = utility::request_client_id(configuration_,
                APPLICATION_NAME_NOT_PREDEFINED + std::to_string(i),
                VSOMEIP_CLIENT_UNSET);
        EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
        if (its_client_id != VSOMEIP_CLIENT_UNSET) {
            if (i > 0 && its_client_ids.back() != its_biggest_client) {
                EXPECT_LT(its_client_ids.back(), its_client_id);
            }
            its_client_ids.push_back(its_client_id);
        } else {
            ADD_FAILURE() << "Received VSOMEIP_CLIENT_UNSET "
                    << static_cast<std::uint32_t>(i);
        }
    }

    // check limit is reached
    its_illegal_client_id = 0xFFFF;
    its_illegal_client_id = utility::request_client_id(configuration_,
            APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
    EXPECT_EQ(VSOMEIP_CLIENT_UNSET, its_illegal_client_id);

    // release all
    for (const client_t c : its_client_ids) {
        utility::release_client_id(configuration_->get_network(), c);
    }
}

TEST_F(client_id_utility_test, request_released_client_id_after_maximum_client_id_is_assigned) {
    std::vector<client_t> its_client_ids;
    std::uint16_t its_max_clients(0);
    for (int var = 0; var < __builtin_popcount(static_cast<std::uint16_t>(~diagnosis_mask_)); ++var) {
        its_max_clients = static_cast<std::uint16_t>(its_max_clients | (1 << var));
    }
    const std::uint16_t max_possible_clients = its_max_clients;
    // -1 for the routing manager, -2 as two predefined client IDs are present
    // in the json file which aren't assigned via autoconfiguration
    const std::uint16_t max_allowed_clients = static_cast<std::uint16_t>(max_possible_clients - 2u);

    // acquire (almost) maximum amount of client IDs
    for (std::uint16_t i = 0; i < max_allowed_clients - 1; i++) {
        client_t its_client_id = utility::request_client_id(configuration_,
                APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
        EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
        if (its_client_id != VSOMEIP_CLIENT_UNSET) {
            if (i > 0) {
                EXPECT_LT(its_client_ids.back(), its_client_id);
            }
            its_client_ids.push_back(its_client_id);
        } else {
            ADD_FAILURE()<< "Received VSOMEIP_CLIENT_UNSET "
            << static_cast<std::uint32_t>(i);
        }
    }

    // release a client ID
    utility::release_client_id(configuration_->get_network(), its_client_ids[10]);

    // requesting an ID should return the maximum possible ID
    client_t its_max_client_id = utility::request_client_id(configuration_,
            APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
    EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_max_client_id);
    its_client_ids.push_back(its_max_client_id);

    // requesting an ID should work as we have released one before
    client_t its_client_id = utility::request_client_id(configuration_,
            APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
    EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
    its_client_ids.push_back(its_client_id);

    // requesting an ID should not work as all IDs are in use now
    client_t its_illegal_client_id = utility::request_client_id(configuration_,
            APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
    EXPECT_EQ(VSOMEIP_CLIENT_UNSET, its_illegal_client_id);

    // release another ID
    utility::release_client_id(configuration_->get_network(), its_client_ids[5]);

    its_client_id = utility::request_client_id(configuration_,
            APPLICATION_NAME_NOT_PREDEFINED, VSOMEIP_CLIENT_UNSET);
    EXPECT_NE(VSOMEIP_CLIENT_UNSET, its_client_id);
    its_client_ids.push_back(its_client_id);

    // release all
    for (const client_t c : its_client_ids) {
        utility::release_client_id(configuration_->get_network(), c);
    }
    its_client_ids.clear();
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
