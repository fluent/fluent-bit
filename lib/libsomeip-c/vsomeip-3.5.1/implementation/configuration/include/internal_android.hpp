// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_INTERNAL_HPP_
#define VSOMEIP_V3_INTERNAL_HPP_

#include <cstdint>
#include <limits>
#include <memory>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/structured_types.hpp>

#define VSOMEIP_ENV_APPLICATION_NAME            "VSOMEIP_APPLICATION_NAME"
#define VSOMEIP_ENV_CONFIGURATION               "VSOMEIP_CONFIGURATION"
#define VSOMEIP_ENV_CONFIGURATION_MODULE        "VSOMEIP_CONFIGURATION_MODULE"
#define VSOMEIP_ENV_E2E_PROTECTION_MODULE       "VSOMEIP_E2E_PROTECTION_MODULE"
#define VSOMEIP_ENV_MANDATORY_CONFIGURATION_FILES "VSOMEIP_MANDATORY_CONFIGURATION_FILES"
#define VSOMEIP_ENV_LOAD_PLUGINS                "VSOMEIP_LOAD_PLUGINS"
#define VSOMEIP_ENV_CLIENTSIDELOGGING           "VSOMEIP_CLIENTSIDELOGGING"

#define VSOMEIP_DEFAULT_CONFIGURATION_FILE      "/vendor/run/etc/vsomeip.json"
#define VSOMEIP_LOCAL_CONFIGURATION_FILE        "./vsomeip.json"
#define VSOMEIP_MANDATORY_CONFIGURATION_FILES                                                      \
    "vsomeip_std.json,vsomeip_app.json,vsomeip_events.json,vsomeip_plc.json,vsomeip_log.json,"     \
    "vsomeip_security.json,vsomeip_whitelist.json,vsomeip_policy_extensions.json,vsomeip_portcfg." \
    "json"

#define VSOMEIP_DEFAULT_CONFIGURATION_FOLDER    "/vendor/run/etc/vsomeip"
#define VSOMEIP_DEBUG_CONFIGURATION_FOLDER      "/var/opt/public/sin/vsomeip/"
#define VSOMEIP_LOCAL_CONFIGURATION_FOLDER      "./vsomeip"

// VSOMEIP_BASE_PATH should be specified in Android.bp or/and Android.mk file via c/c++ compiler flags.
// #define VSOMEIP_BASE_PATH                       "/storage/"

#define VSOMEIP_ROUTING_HOST_PORT_DEFAULT       31490

#define VSOMEIP_CFG_LIBRARY                     "libvsomeip_cfg.so"

#define VSOMEIP_SD_LIBRARY                      "libvsomeip_sd.so"

#define VSOMEIP_E2E_LIBRARY                     "libvsomeip_e2e.so"

#define VSOMEIP_SEC_LIBRARY                     "libvsomeip-sec.so.1"

#define VSOMEIP_ROUTING                         "vsomeipd"
#define VSOMEIP_ROUTING_CLIENT                  0
#define VSOMEIP_ROUTING_INFO_SIZE_INIT          256

#define VSOMEIP_CLIENT_UNSET                    0xFFFF

#define VSOMEIP_UNICAST_ADDRESS                 "127.0.0.1"
#define VSOMEIP_NETMASK                         "255.255.255.0"
#define VSOMEIP_PREFIX                          24

#define VSOMEIP_DEFAULT_CONNECT_TIMEOUT         100
#define VSOMEIP_MAX_CONNECT_TIMEOUT             1600
#define VSOMEIP_DEFAULT_CONNECTING_TIMEOUT      500
#define VSOMEIP_DEFAULT_FLUSH_TIMEOUT           1000
#define VSOMEIP_ROUTING_ROOT_RECONNECT_RETRIES  10000
#define VSOMEIP_ROUTING_ROOT_RECONNECT_INTERVAL 10  // miliseconds

#define VSOMEIP_DEFAULT_SHUTDOWN_TIMEOUT        5000

#define VSOMEIP_DEFAULT_QUEUE_WARN_SIZE         102400

#define VSOMEIP_MAX_TCP_CONNECT_TIME            5000
#define VSOMEIP_MAX_TCP_RESTART_ABORTS          5
#define VSOMEIP_MAX_TCP_SENT_WAIT_TIME          10000

#define VSOMEIP_MAX_NETLINK_RETRIES             3

#define VSOMEIP_TP_MAX_SEGMENT_LENGTH_DEFAULT   1392

#define VSOMEIP_DEFAULT_BUFFER_SHRINK_THRESHOLD 5

#define VSOMEIP_DEFAULT_WATCHDOG_TIMEOUT        5000
#define VSOMEIP_DEFAULT_MAX_MISSING_PONGS       3

#define VSOMEIP_DEFAULT_UDP_RCV_BUFFER_SIZE     1703936

#define VSOMEIP_DEFAULT_IO_THREAD_COUNT         2
#define VSOMEIP_DEFAULT_IO_THREAD_NICE_LEVEL    0

#define VSOMEIP_MAX_DISPATCHERS                 10
#define VSOMEIP_MAX_DISPATCH_TIME               100

#define VSOMEIP_MAX_WAIT_TIME_DETACHED_THREADS  5

#define VSOMEIP_REQUEST_DEBOUNCE_TIME           10
#define VSOMEIP_DEFAULT_STATISTICS_MAX_MSG      50
#define VSOMEIP_DEFAULT_STATISTICS_MIN_FREQ     50
#define VSOMEIP_DEFAULT_STATISTICS_INTERVAL     10000

#define VSOMEIP_DEFAULT_MAX_REMOTE_SUBSCRIBERS  3

#define VSOMEIP_MAX_WAIT_SENT                   5

#define VSOMEIP_LOCAL_CLIENT_ENDPOINT_RECV_BUFFER_SIZE  19

#define VSOMEIP_MINIMUM_CHECK_TTL_TIMEOUT       100
#define VSOMEIP_SETSOCKOPT_TIMEOUT_US           500000  // us

#define LOCAL_TCP_PORT_WAIT_TIME                100
#define LOCAL_TCP_PORT_MAX_WAIT_TIME            10000

#include <pthread.h>

#define VSOMEIP_DATA_ID                         0x677D
#define VSOMEIP_DIAGNOSIS_ADDRESS               0x01

#define VSOMEIP_DEFAULT_SHM_PERMISSION          0666
#define VSOMEIP_DEFAULT_UDS_PERMISSIONS         0666

#define VSOMEIP_ROUTING_READY_MESSAGE           "SOME/IP routing ready."

#ifndef VSOMEIP_VERSION
#define VSOMEIP_VERSION "unknown version"
#endif

namespace vsomeip_v3 {

typedef enum {
    RIE_ADD_CLIENT = 0x0,
    RIE_ADD_SERVICE_INSTANCE = 0x1,
    RIE_DEL_SERVICE_INSTANCE = 0x2,
    RIE_DEL_CLIENT = 0x3,
} routing_info_entry_e;

typedef enum {
    SUBSCRIPTION_ACKNOWLEDGED,
    SUBSCRIPTION_NOT_ACKNOWLEDGED,
    IS_SUBSCRIBING
} subscription_state_e;

inline constexpr std::uint32_t MESSAGE_SIZE_UNLIMITED = std::numeric_limits<std::uint32_t>::max();

inline constexpr std::uint32_t QUEUE_SIZE_UNLIMITED = std::numeric_limits<std::uint32_t>::max();

#define VSOMEIP_DEFAULT_NPDU_DEBOUNCING_NANO         2 * 1000 * 1000
#define VSOMEIP_DEFAULT_NPDU_MAXIMUM_RETENTION_NANO  5 * 1000 * 1000

inline constexpr std::uint32_t MAX_RECONNECTS_UNLIMITED = std::numeric_limits<std::uint32_t>::max();

inline constexpr std::uint32_t ANY_UID = 0xFFFFFFFF;
inline constexpr std::uint32_t ANY_GID = 0xFFFFFFFF;

enum class port_type_e {
    PT_OPTIONAL,
    PT_SECURE,
    PT_UNSECURE,
    PT_UNKNOWN
};

typedef uint8_t partition_id_t;
const partition_id_t VSOMEIP_DEFAULT_PARTITION_ID = 0;

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_INTERNAL_HPP_
