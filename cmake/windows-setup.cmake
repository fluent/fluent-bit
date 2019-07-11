# Custom build settings for Windows (MSVC)
#
# Not all plugins are supported on Windows yet. This file tweaks
# the build flags so that we can compile fluent-bit on it.

set(FLB_REGEX                 Yes)
set(FLB_BACKTRACE              No)
set(FLB_LUAJIT                Yes)
set(FLB_EXAMPLES              Yes)
set(FLB_PARSER                Yes)
set(FLB_TLS                   Yes)

# Windows does not support strptime(3)
set(FLB_SYSTEM_STRPTIME        No)

# INPUT plugins
# =============
set(FLB_IN_CPU                 No)
set(FLB_IN_DISK                No)
set(FLB_IN_EXEC                No)
set(FLB_IN_FORWARD             No)
set(FLB_IN_HEALTH              No)
set(FLB_IN_HTTP                No)
set(FLB_IN_MEM                 No)
set(FLB_IN_KMSG                No)
set(FLB_IN_LIB                Yes)
set(FLB_IN_RANDOM             Yes)
set(FLB_IN_SERIAL              No)
set(FLB_IN_STDIN               No)
set(FLB_IN_SYSLOG              No)
set(FLB_IN_TAIL               Yes)
set(FLB_IN_TCP                 No)
set(FLB_IN_MQTT                No)
set(FLB_IN_HEAD                No)
set(FLB_IN_PROC                No)
set(FLB_IN_SYSTEMD             No)
set(FLB_IN_DUMMY              Yes)
set(FLB_IN_NETIF               No)
set(FLB_IN_STORAGE_BACKLOG     No)

# OUTPUT plugins
# ==============
set(FLB_OUT_AZURE              No)
set(FLB_OUT_BIGQUERY           No)
set(FLB_OUT_COUNTER           Yes)
set(FLB_OUT_ES                Yes)
set(FLB_OUT_EXIT               No)
set(FLB_OUT_FORWARD           Yes)
set(FLB_OUT_GELF               No)
set(FLB_OUT_HTTP              Yes)
set(FLB_OUT_INFLUXDB           No)
set(FLB_OUT_NATS               No)
set(FLB_IN_NATS                No)
set(FLB_OUT_PLOT               No)
set(FLB_OUT_FILE              Yes)
set(FLB_OUT_TD                 No)
set(FLB_OUT_RETRY              No)
set(FLB_OUT_SPLUNK            Yes)
set(FLB_OUT_STACKDRIVER        No)
set(FLB_OUT_STDOUT            Yes)
set(FLB_OUT_LIB                No)
set(FLB_OUT_NULL              Yes)
set(FLB_OUT_FLOWCOUNTER       Yes)
set(FLB_OUT_KAFKA             Yes)
set(FLB_OUT_KAFKA_REST         No)

# FILTER plugins
# ==============
set(FLB_FILTER_GREP           Yes)
set(FLB_FILTER_MODIFY         Yes)
set(FLB_FILTER_STDOUT         Yes)
set(FLB_FILTER_PARSER          No)
set(FLB_FILTER_KUBERNETES      No)
set(FLB_FILTER_THROTTLE        No)
set(FLB_FILTER_NEST            No)
set(FLB_FILTER_LUA            Yes)
set(FLB_FILTER_RECORD_MODIFIER Yes)

# Search bison and flex executables
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  find_package(FLEX)
  find_package(BISON)

  if (NOT (${FLEX_FOUND} AND ${BISON_FOUND}))
    message(STATUS "flex and bison not found. Disable stream_processor building.")
    set(FLB_STREAM_PROCESSOR No)
  endif()
endif()
