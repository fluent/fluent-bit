// Copyright (C) 2022 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/security.hpp"
#include <vsomeip/internal/logger.hpp>
#include <vsomeip/internal/plugin_manager.hpp>
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif
#include "../../configuration/include/configuration_plugin.hpp"
#include "../../configuration/include/configuration_impl.hpp"

#include <array>
#include <iomanip>
#include <tuple>

#ifndef _WIN32
#include <dlfcn.h>
#endif

template<class T_>
std::function<T_> security_load_function(void *_library, std::string const &_name) {
    void *its_function;
#ifdef _WIN32
    its_function = GetProcAddress(reinterpret_cast<HMODULE>(_library), _name.c_str());
#else
    its_function = dlsym(_library, _name.c_str());
#endif
    if (!its_function) {
        VSOMEIP_ERROR << __func__
                  << ": security library misses \""
                  << _name
                  << "\" function.";
        return nullptr;
    }

    return reinterpret_cast<T_*>(its_function);
}

#define VSOMEIP_SECURITY_LOAD_IMPL(symbol, variable) \
    auto variable = security_load_function<decltype(symbol)>(its_library, #symbol); \
    if (!variable) { \
        its_manager->unload_library(its_library); \
        return false; \
    }

#define VSOMEIP_SECURITY_LOAD(name) \
    VSOMEIP_SECURITY_LOAD_IMPL(vsomeip_sec_##name, loaded_##name)

#define VSOMEIP_SECURITY_POLICY_LOAD(name) \
    VSOMEIP_SECURITY_LOAD_IMPL(vsomeip_sec_policy_##name, loaded_##name)

#define VSOMEIP_SECURITY_ASSIGN_FUNCTION(name) \
    name = loaded_##name

namespace vsomeip_v3 {

security::security(std::shared_ptr<policy_manager_impl> _policy_manager):
    policy_manager_(_policy_manager) {

    initialize = [&]() -> vsomeip_sec_policy_result_t {
        return default_initialize();
    };

    authenticate_router = [&](const vsomeip_sec_client_t *_server) -> vsomeip_sec_acl_result_t {
        return default_authenticate_router(_server);
    };

    is_client_allowed_to_offer = [&](const vsomeip_sec_client_t *_client,
        vsomeip_sec_service_id_t _service, vsomeip_sec_instance_id_t _instance) -> vsomeip_sec_acl_result_t {
        return default_is_client_allowed_to_offer(_client, _service, _instance);
    };

    is_client_allowed_to_request = [&](const vsomeip_sec_client_t *_client,
        vsomeip_sec_service_id_t _service, vsomeip_sec_instance_id_t _instance) -> vsomeip_sec_acl_result_t {
            return default_is_client_allowed_to_request(_client, _service, _instance);
    };

    is_client_allowed_to_access_member = [&](const vsomeip_sec_client_t *_client,
        vsomeip_sec_service_id_t _service, vsomeip_sec_instance_id_t _instance,
        vsomeip_sec_member_id_t _member) -> vsomeip_sec_acl_result_t {
            return default_is_client_allowed_to_access_member(_client, _service,
                    _instance, _member);
    };

    sync_client = [&](vsomeip_sec_client_t *_client) {
        return default_sync_client(_client);
    };
}

bool
security::load() {
    if (auto its_manager = plugin_manager::get()) {
        if (auto its_library = its_manager->load_library(VSOMEIP_SEC_LIBRARY)) {

            VSOMEIP_SECURITY_POLICY_LOAD(initialize);
            VSOMEIP_SECURITY_POLICY_LOAD(authenticate_router);
            VSOMEIP_SECURITY_POLICY_LOAD(is_client_allowed_to_offer);
            VSOMEIP_SECURITY_POLICY_LOAD(is_client_allowed_to_request);
            VSOMEIP_SECURITY_POLICY_LOAD(is_client_allowed_to_access_member);
            VSOMEIP_SECURITY_LOAD(sync_client);

            // All symbols could be loaded, assign them
            VSOMEIP_SECURITY_ASSIGN_FUNCTION(initialize);
            VSOMEIP_SECURITY_ASSIGN_FUNCTION(authenticate_router);
            VSOMEIP_SECURITY_ASSIGN_FUNCTION(is_client_allowed_to_offer);
            VSOMEIP_SECURITY_ASSIGN_FUNCTION(is_client_allowed_to_request);
            VSOMEIP_SECURITY_ASSIGN_FUNCTION(is_client_allowed_to_access_member);
            VSOMEIP_SECURITY_ASSIGN_FUNCTION(sync_client);

            // Symbol loading complete, success!
            return true;
        } else {
#ifdef _WIN32
            VSOMEIP_ERROR << "vSomeIP Security: Loading " << VSOMEIP_SEC_LIBRARY << " failed.";
#else
            VSOMEIP_ERROR << "vSomeIP Security: " << dlerror();
#endif
        }
    }

    return false;
}

//
// Default interface implementation
//
vsomeip_sec_policy_result_t
security::default_initialize() {
    return VSOMEIP_SEC_POLICY_OK;
}

vsomeip_sec_acl_result_t
security::default_authenticate_router(const vsomeip_sec_client_t *_server) {

    if (_server && _server->port != VSOMEIP_SEC_PORT_UNUSED)
        return VSOMEIP_SEC_OK;

    if (policy_manager_->check_routing_credentials(_server))
        return VSOMEIP_SEC_OK;
    else
        return VSOMEIP_SEC_PERM_DENIED;
}

vsomeip_sec_acl_result_t
security::default_is_client_allowed_to_offer(const vsomeip_sec_client_t *_client,
        vsomeip_sec_service_id_t _service, vsomeip_sec_instance_id_t _instance) {

    if (_client && _client->port != VSOMEIP_SEC_PORT_UNUSED)
        return VSOMEIP_SEC_OK;

    if (policy_manager_->is_offer_allowed(_client, _service, _instance))
        return VSOMEIP_SEC_OK;
    else
        return VSOMEIP_SEC_PERM_DENIED;
}

vsomeip_sec_acl_result_t
security::default_is_client_allowed_to_request(const vsomeip_sec_client_t *_client,
        vsomeip_sec_service_id_t _service, vsomeip_sec_instance_id_t _instance) {

    if (_client && _client->port != VSOMEIP_SEC_PORT_UNUSED)
        return VSOMEIP_SEC_OK;

    if (policy_manager_->is_client_allowed(_client, _service, _instance, 0x00, true))
        return VSOMEIP_SEC_OK;
    else
        return VSOMEIP_SEC_PERM_DENIED;
}

vsomeip_sec_acl_result_t
security::default_is_client_allowed_to_access_member(const vsomeip_sec_client_t *_client,
        vsomeip_sec_service_id_t _service, vsomeip_sec_instance_id_t _instance,
        vsomeip_sec_member_id_t _member) {

    if (_client && _client->port != VSOMEIP_SEC_PORT_UNUSED)
        return VSOMEIP_SEC_OK;

    if (policy_manager_->is_client_allowed(_client, _service, _instance, _member, false))
        return VSOMEIP_SEC_OK;
    else
        return VSOMEIP_SEC_PERM_DENIED;
}

void
security::default_sync_client(vsomeip_sec_client_t *_client) {
    (void)_client;
}

} // namespace vsomeip_v3
