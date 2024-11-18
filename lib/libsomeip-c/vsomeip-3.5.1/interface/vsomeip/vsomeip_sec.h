// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SECURITY_VSOMEIP_SEC_H_
#define VSOMEIP_V3_SECURITY_VSOMEIP_SEC_H_

#define VSOMEIP_SEC_PORT_UNUSED  0
#define VSOMEIP_SEC_PORT_UNSET   0xFFFF

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>

typedef uint16_t vsomeip_sec_service_id_t;
typedef uint16_t vsomeip_sec_instance_id_t;
typedef uint16_t vsomeip_sec_member_id_t;    // SOME/IP method or event

typedef uint32_t vsomeip_sec_ip_addr_t;      // ip address in network byte order
typedef uint16_t vsomeip_sec_network_port_t; // network port in network byte order

#ifndef __unix__
typedef uint32_t uid_t;
typedef uint32_t gid_t;
#endif

typedef struct {
    uid_t user;
    gid_t group;

    vsomeip_sec_ip_addr_t host;
    vsomeip_sec_network_port_t port; // VSOMEIP_SEC_PORT_UNUSED --> UDS; ]0, VSOMEIP_SEC_PORT_UNSET] --> TCP
} vsomeip_sec_client_t;

typedef enum {
    VSOMEIP_SEC_OK,
    VSOMEIP_SEC_PERM_DENIED
} vsomeip_sec_acl_result_t;

typedef enum {
    VSOMEIP_SEC_POLICY_OK,
    VSOMEIP_SEC_POLICY_NOT_FOUND,
    VSOMEIP_SEC_POLICY_INVALID
} vsomeip_sec_policy_result_t;

/**
 * Load the policy and initialize policy plugin functionality.
 * This function MUST be called before any other function in this library can be called.
 * It will return whether loading the policy was successful or if there was some problem
 * during initialization.
 *
 * Please note that the policy initializer does not take any additional arguments. It is assumed
 * here tha the policy plugin libraries have some out-of-bounds methods to, e.g., find the policy
 * file.
 *
 * The function may be called multiple times (even from multiple threads) without problems.
 */
 vsomeip_sec_policy_result_t vsomeip_sec_policy_initialize();

/**
 * Authenticate connection with vSomeIP router.
 *
 * vSomeIP router (vsomeipd) has by definition unlimited access to other vSomeIP applications.
 * Therefore, EVERY connection with the router must be authenticated and then any command from/to
 * vsomeipd is implicitly allowed.
 *
 * This method MUST be called to ensure that the remote end is supposed to act as
 * vSomeIP routing manager.
 *
 */
vsomeip_sec_acl_result_t vsomeip_sec_policy_authenticate_router(const vsomeip_sec_client_t *router);


/*
 * ### RPC
 */

/**
 * Check if a server is authorised to offer a specific service / instance
 *
 * vsomeip_sec_policy_is_client_allowed_to_offer checks if \p server is allowed to offer a \p
 * service by the security policy.
 *
 * This API MUST be called by vSomeIP clients before sending requests and before
 * processing responses. It and SHOULD be called at the router for every service offer before
 * distributing it among the clients.
 *
 * @note
 * Both, method calls and subscribe-notify communications are end-to-end
 * authenticated. Therefore, authentication of the server at the router side is optional but
 * recommended. Doing so would  help to detect system missconfiguration and simplify
 * application debugging.
 *
 * @note
 * Due to asynchronous nature of SOME/IP method calls, to deliver a method response, server
 * establishes a separate socket which destination client must be authenticated. This method
 * does exactly that.
 *
 * @note
 * While client access may be restricted to certain methods or events, servers are always
 * allowed to offer.
 */
vsomeip_sec_acl_result_t vsomeip_sec_policy_is_client_allowed_to_offer(
    const vsomeip_sec_client_t *server,
    vsomeip_sec_service_id_t service, vsomeip_sec_instance_id_t instance);



/**
 * Check if client is allowed to request a service.
 *
 * This method MUST be called at the server/stub side before serving a client request. It may
 * additionally be used by vsomeipd when servicing service discovery so that clients that do not
 * have the permission to request a certain service cannot (even) successfully discover it.
 *
 */
vsomeip_sec_acl_result_t vsomeip_sec_policy_is_client_allowed_to_request(
    const vsomeip_sec_client_t *client,
    vsomeip_sec_service_id_t service, vsomeip_sec_instance_id_t instance);


/**
 * Check if client is allowed to access a specific SOME/IP method.
 *
 * SOME/IP does not really distinguish between methods and events. It just handles everything
 * via a uint16 member identifier. The identifiers below 0x7FFF are used for methods, identifier
 * starting at 0x8000 are used for events. So we just have one method to check if the client is
 * allowed to interact with a specific member.
 *
 * This method MUST be called at the server/stub side before processing a request that triggers
 * a specific method or completes event registration.
 */
vsomeip_sec_acl_result_t vsomeip_sec_policy_is_client_allowed_to_access_member(
    const vsomeip_sec_client_t *client,
    vsomeip_sec_service_id_t service, vsomeip_sec_instance_id_t instance, vsomeip_sec_member_id_t member);


/**
 * Provides user and group identifiers for a given host address / port combination.
 *
 * Note: For UDS (aka port=0), calling this function is a no-op.
 */
void vsomeip_sec_sync_client(vsomeip_sec_client_t *client);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // VSOMEIP_V3_SECURITY_VSOMEIP_SEC_H_
