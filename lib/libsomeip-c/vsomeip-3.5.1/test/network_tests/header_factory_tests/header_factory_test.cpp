// Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <vsomeip/vsomeip.hpp>

#include "../someip_test_globals.hpp"
#include <common/vsomeip_app_utilities.hpp>

class someip_header_factory_test: public ::testing::Test
{
protected:
    std::shared_ptr<vsomeip::message> request_;
    std::shared_ptr<vsomeip::message> response_;
    std::shared_ptr<vsomeip::message> notification_;
    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> message_;

    vsomeip::service_t service_id_ = vsomeip_test::TEST_SERVICE_SERVICE_ID;
    vsomeip::method_t method_id_ = vsomeip_test::TEST_SERVICE_METHOD_ID;
    vsomeip::instance_t instance_id_ = vsomeip_test::TEST_SERVICE_INSTANCE_ID;
    vsomeip::interface_version_t interface_version_ = 0x01;
    vsomeip::client_t client_id_ = vsomeip_test::TEST_CLIENT_CLIENT_ID;
    vsomeip::session_t session_id_ = vsomeip_test::TEST_INITIAL_SESSION_ID;
};

TEST_F(someip_header_factory_test, create_request_test)
{
    ASSERT_TRUE(request_.get() == nullptr);
    request_ = vsomeip::runtime::get()->create_request();

    // check that returned shared_ptr is not null
    ASSERT_TRUE(request_.get() != nullptr);

    // Check the protocol version
    // this shall be set to 0x01 according to the spec. TR_SOMEIP_00052
    ASSERT_EQ(request_->get_protocol_version(), 0x01);
    // Check the message type
    // this shall be 0x00 (REQUEST) according to the spec. TR_SOMEIP_00055
    ASSERT_EQ(request_->get_message_type(), vsomeip::message_type_e::MT_REQUEST);
    // Check the return code
    // this shall be 0x00 (E_OK) according to the spec. TR_SOMEIP_00058
    ASSERT_EQ(request_->get_return_code(), vsomeip::return_code_e::E_OK);

}

TEST_F(someip_header_factory_test, create_request_and_response_test)
{
    ASSERT_TRUE(request_.get() == nullptr);
    request_ = vsomeip::runtime::get()->create_request();
    // check that returned shared_ptr is not null
    ASSERT_TRUE(request_.get() != nullptr);

    request_->set_service(service_id_);
    request_->set_method(method_id_);
    request_->set_interface_version(interface_version_);
    // set the request_id (client_id + session_id). This normally is set by the
    // application_impl::send() if a request is send, we set it here to test the
    // correct initialization of the response
    request_->set_client(client_id_);
    request_->set_session(session_id_);

    ASSERT_TRUE(response_.get() == nullptr);
    response_ = vsomeip::runtime::get()->create_response(request_);
    // check that returned shared_ptr is not null
    ASSERT_TRUE(response_.get() != nullptr);

    ASSERT_EQ(response_->get_service(), request_->get_service());
    ASSERT_EQ(response_->get_method(), request_->get_method());
    ASSERT_EQ(response_->get_session(), request_->get_session());

    // length? --> gets only set if a payload is added

    ASSERT_EQ(response_->get_protocol_version(), request_->get_protocol_version());
    ASSERT_EQ(response_->get_interface_version(), request_->get_interface_version());

    // Check the message type
    // this shall be 0x00 (REQUEST) according to the spec. TR_SOMEIP_00055
    ASSERT_EQ(request_->get_message_type(), vsomeip::message_type_e::MT_REQUEST);

    // Check the message type
    // this shall be 0x80 (RESPONSE) according to the spec. TR_SOMEIP_00055
    ASSERT_EQ(response_->get_message_type(), vsomeip::message_type_e::MT_RESPONSE);

    // Check the return code
    // this shall be 0x00 (E_OK) according to the spec. TR_SOMEIP_00058
    // and TR_SOMEIP_00191
    ASSERT_EQ(response_->get_return_code(), vsomeip::return_code_e::E_OK);

}

TEST_F(someip_header_factory_test, create_notification_test)
{
    ASSERT_TRUE(notification_.get() == nullptr);
    notification_ = vsomeip::runtime::get()->create_notification();

    // check that returned shared_ptr is not null
    ASSERT_TRUE(notification_.get() != nullptr);

    // Check the protocol version
    // this shall be set to 0x01 according to the spec. TR_SOMEIP_00052
    ASSERT_EQ(notification_->get_protocol_version(), 0x01);
    // Check the message type
    // this shall be 0x02 (NOTIFICATION) according to the spec. TR_SOMEIP_00055
    ASSERT_EQ(notification_->get_message_type(), vsomeip::message_type_e::MT_NOTIFICATION);
    // Check the return code
    // this shall be 0x00 (E_OK) according to the spec. TR_SOMEIP_00058
    ASSERT_EQ(notification_->get_return_code(), vsomeip::return_code_e::E_OK);
}

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
