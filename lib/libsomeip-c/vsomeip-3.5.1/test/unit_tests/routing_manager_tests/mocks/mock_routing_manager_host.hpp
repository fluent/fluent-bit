// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gmock/gmock.h>
#include "../../../../implementation/routing/include/routing_manager_host.hpp"

using namespace vsomeip_v3;
class mock_routing_manager_host : public routing_manager_host {
public:

    MOCK_METHOD(client_t, get_client, (), (const, override));
    MOCK_METHOD(void, set_client, (const client_t &_client), (override));
    MOCK_METHOD(session_t, get_session, (bool _is_request), (override));

    MOCK_METHOD(const vsomeip_sec_client_t* ,get_sec_client, (), (const, override));
    MOCK_METHOD(void, set_sec_client_port, (port_t _port), (override));

    MOCK_METHOD(const std::string &, get_name, (), (const, override));
    MOCK_METHOD(std::shared_ptr<configuration>, get_configuration, (), (const, override));
    MOCK_METHOD(boost::asio::io_context &, get_io, (), (override));

    MOCK_METHOD(void, on_availability, (service_t _service, instance_t _instance,
            availability_state_e _state,
            major_version_t _major,
            minor_version_t _minor), (override));
    MOCK_METHOD(void, on_state, (state_type_e _state), (override));
    MOCK_METHOD(void, on_message, (std::shared_ptr<message> &&_message), (override));
    MOCK_METHOD(void, on_subscription, (service_t _service, instance_t _instance,
        eventgroup_t _eventgroup,
        client_t _client, const vsomeip_sec_client_t *_sec_client,
        const std::string &_env, bool _subscribed,
        const std::function<void(bool)> &_accepted_cb), (override));
    MOCK_METHOD(void, on_subscription_status, (service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event, uint16_t _error), (override));
    MOCK_METHOD(void, send, (std::shared_ptr<message> _message), (override));
    MOCK_METHOD(void, on_offered_services_info, (
            (std::vector<std::pair<vsomeip_v3::service_t, vsomeip_v3::instance_t>>& _services)), (override));
    MOCK_METHOD(bool, is_routing, (), (const, override));

};
