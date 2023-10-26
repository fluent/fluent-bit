cmake_minimum_required(VERSION 3.12)
project(fluent-bit C)

# CMP0069 ensures that LTO is enabled for all compilers
cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

# Fluent Bit Version
set(FLB_VERSION_MAJOR  2)
set(FLB_VERSION_MINOR  2)
set(FLB_VERSION_PATCH  0)
set(FLB_VERSION_STR "${FLB_VERSION_MAJOR}.${FLB_VERSION_MINOR}.${FLB_VERSION_PATCH}")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(FLB_SYSTEM_WINDOWS On)
  add_definitions(-DFLB_SYSTEM_WINDOWS)
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(FLB_SYSTEM_MACOS On)
  add_definitions(-DFLB_SYSTEM_MACOS)
endif()

# Define macro to identify Linux system
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(FLB_SYSTEM_LINUX On)
  add_definitions(-DFLB_SYSTEM_LINUX)
endif()

# Update CFLAGS
if (MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)

  # Use custom CFLAGS for MSVC
  #
  #   /Zi ...... Generate pdb files.
  #   /MT ...... Static link C runtimes.
  #   /wd4711 .. C4711 (function selected for inline expansion)
  #   /wd4100 .. C4100 (unreferenced formal parameter)
  #   /wd5045 .. C5045 (Spectre mitigation)
  #
  set(CMAKE_C_FLAGS "/DWIN32 /D_WINDOWS /DNDEBUG /O2 /Zi /wd4100 /wd4711 /wd5045")
  set(CMAKE_EXE_LINKER_FLAGS "/Debug /INCREMENTAL:NO")
  set(CMAKE_BUILD_TYPE None)

  # Use add_compile_options() to set /MT since Visual Studio
  # Generator does not notice /MT in CMAKE_C_FLAGS.
  add_compile_options(/MT)
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  # The following flags are to enhance security, but it may impact performance,
  # we disable them by default.
  if (FLB_WASM_STACK_PROTECT)
    if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
      set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftrapv -D_FORTIFY_SOURCE=2")
    endif ()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong --param ssp-buffer-size=4")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack,-z,relro,-z,now")
  endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FLB_FILENAME__=__FILE__")

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "armv7l")
  set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -latomic")
  set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -latomic")
endif()
if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  set(FLB_SYSTEM_FREEBSD On)
  add_definitions(-DFLB_SYSTEM_FREEBSD)
  set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -lutil")
  set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -lutil")
endif()

# *BSD is not supported platform for wasm-micro-runtime except for FreeBSD.
# Now, we should be disabled for these platforms.
if(NOT FLB_SYSTEM_FREEBSD AND ${CMAKE_SYSTEM_NAME} MATCHES "BSD")
  message(STATUS "This platform is not supported for WASM feature so disabled.")
  set(FLB_WASM OFF)
elseif(FLB_SYSTEM_FREEBSD)
  message(STATUS "Some of FreeBSD environment do not work with hardware boundary check so disabled.")
  set(WAMR_DISABLE_STACK_HW_BOUND_CHECK 1)
endif()

include(GNUInstallDirs)
include(ExternalProject)
include(cmake/FindJournald.cmake)
include(cmake/FindMonkey.cmake)
include(cmake/macros.cmake)
include(cmake/platform_feature_checks.cmake)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

# Output paths
set(FLB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

# Build Options
option(FLB_ALL                 "Enable all features"                         No)
option(FLB_DEBUG               "Build with debug mode (-g)"                 Yes)
option(FLB_RELEASE             "Build with release mode (-O2 -g -DNDEBUG)"   No)
set(FLB_IPO "ReleaseOnly" CACHE STRING "Build with interprocedural optimization")
set_property(CACHE FLB_IPO PROPERTY STRINGS "On;Off;ReleaseOnly")
option(FLB_SMALL               "Optimise for small size"       No)
option(FLB_COVERAGE            "Build with code-coverage"      No)
option(FLB_JEMALLOC            "Build with Jemalloc support"   No)
option(FLB_REGEX               "Build with Regex support"     Yes)
option(FLB_UTF8_ENCODER        "Build with UTF8 encoding support" Yes)
option(FLB_PARSER              "Build with Parser support"    Yes)
option(FLB_TLS                 "Build with SSL/TLS support"   Yes)
option(FLB_BINARY              "Build executable binary"      Yes)
option(FLB_EXAMPLES            "Build examples"               Yes)
option(FLB_SHARED_LIB          "Build shared library"         Yes)
option(FLB_VALGRIND            "Enable Valgrind support"       No)
option(FLB_TRACE               "Enable trace mode"             No)
option(FLB_CHUNK_TRACE         "Enable chunk traces"          Yes)
option(FLB_TESTS_RUNTIME       "Enable runtime tests"          No)
option(FLB_TESTS_INTERNAL      "Enable internal tests"         No)
option(FLB_TESTS_INTERNAL_FUZZ "Enable internal fuzz tests"    No)
option(FLB_TESTS_OSSFUZZ       "Enable OSS-Fuzz build"         No)
option(FLB_MTRACE              "Enable mtrace support"         No)
option(FLB_POSIX_TLS           "Force POSIX thread storage"    No)
option(FLB_INOTIFY             "Enable inotify support"       Yes)
option(FLB_SQLDB               "Enable SQL embedded DB"       Yes)
option(FLB_HTTP_SERVER         "Enable HTTP Server"           Yes)
option(FLB_BACKTRACE           "Enable stacktrace support"    Yes)
option(FLB_LUAJIT              "Enable Lua Scripting support" Yes)
option(FLB_RECORD_ACCESSOR     "Enable record accessor"       Yes)
option(FLB_SIGNV4              "Enable AWS Signv4 support"    Yes)
option(FLB_AWS                 "Enable AWS support"           Yes)
option(FLB_STATIC_CONF         "Build binary using static configuration")
option(FLB_STREAM_PROCESSOR    "Enable Stream Processor"                    Yes)
option(FLB_CORO_STACK_SIZE     "Set coroutine stack size")
option(FLB_AVRO_ENCODER        "Build with Avro encoding support"            No)
option(FLB_AWS_ERROR_REPORTER  "Build with aws error reporting support"      No)
option(FLB_ARROW               "Build with Apache Arrow support"             No)
option(FLB_WINDOWS_DEFAULTS    "Build with predefined Windows settings"     Yes)
option(FLB_WASM                "Build with WASM runtime support"            Yes)
option(FLB_WAMRC               "Build with WASM AOT compiler executable"    No)
option(FLB_WASM_STACK_PROTECT  "Build with WASM runtime with strong stack protector flags" No)

# Native Metrics Support (cmetrics)
option(FLB_METRICS             "Enable metrics support"       Yes)

# Proxy Plugins
option(FLB_PROXY_GO            "Enable Go plugins support"    Yes)

# Built-in Custom Plugins
option(FLB_CUSTOM_CALYPTIA     "Enable Calyptia Support"      Yes)

# Config formats
option(FLB_CONFIG_YAML         "Enable YAML config format"    Yes)

# Built-in Plugins
option(FLB_IN_CPU                      "Enable CPU input plugin"                      Yes)
option(FLB_IN_THERMAL                  "Enable Thermal plugin"                        Yes)
option(FLB_IN_DISK                     "Enable Disk input plugin"                     Yes)
option(FLB_IN_DOCKER                   "Enable Docker input plugin"                   Yes)
option(FLB_IN_DOCKER_EVENTS            "Enable Docker events input plugin"            Yes)
option(FLB_IN_EXEC                     "Enable Exec input plugin"                     Yes)
option(FLB_IN_EXEC_WASI                "Enable Exec WASI input plugin"                Yes)
option(FLB_IN_EVENT_TEST               "Enable Events test plugin"                    Yes)
option(FLB_IN_EVENT_TYPE               "Enable event type plugin"                     Yes)
option(FLB_IN_FLUENTBIT_METRICS        "Enable Fluent Bit metrics  plugin"            Yes)
option(FLB_IN_FORWARD                  "Enable Forward input plugin"                  Yes)
option(FLB_IN_HEALTH                   "Enable Health input plugin"                   Yes)
option(FLB_IN_HTTP                     "Enable HTTP input plugin"                     Yes)
option(FLB_IN_MEM                      "Enable Memory input plugin"                   Yes)
option(FLB_IN_KUBERNETES_EVENTS        "Enable Kubernetes Events plugin"              Yes)
option(FLB_IN_KAFKA                    "Enable Kafka input plugin"                    Yes)
option(FLB_IN_KMSG                     "Enable Kernel log input plugin"               Yes)
option(FLB_IN_LIB                      "Enable library mode input plugin"             Yes)
option(FLB_IN_RANDOM                   "Enable random input plugin"                   Yes)
option(FLB_IN_SERIAL                   "Enable Serial input plugin"                   Yes)
option(FLB_IN_STDIN                    "Enable Standard input plugin"                 Yes)
option(FLB_IN_SYSLOG                   "Enable Syslog input plugin"                   Yes)
option(FLB_IN_TAIL                     "Enable Tail input plugin"                     Yes)
option(FLB_IN_UDP                      "Enable UDP input plugin"                      Yes)
option(FLB_IN_TCP                      "Enable TCP input plugin"                      Yes)
option(FLB_IN_UNIX_SOCKET              "Enable Unix socket input plugin"               No)
option(FLB_IN_MQTT                     "Enable MQTT Broker input plugin"              Yes)
option(FLB_IN_HEAD                     "Enable Head input plugin"                     Yes)
option(FLB_IN_PROC                     "Enable Process input plugin"                  Yes)
option(FLB_IN_SYSTEMD                  "Enable Systemd input plugin"                  Yes)
option(FLB_IN_DUMMY                    "Enable Dummy input plugin"                    Yes)
option(FLB_IN_NGINX_EXPORTER_METRICS   "Enable Nginx Metrics input plugin"            Yes)
option(FLB_IN_NETIF                    "Enable NetworkIF input plugin"                Yes)
option(FLB_IN_WINLOG                   "Enable Windows Log input plugin"               No)
option(FLB_IN_WINSTAT                  "Enable Windows Stat input plugin"              No)
option(FLB_IN_WINEVTLOG                "Enable Windows EvtLog input plugin"            No)
option(FLB_IN_COLLECTD                 "Enable Collectd input plugin"                 Yes)
option(FLB_IN_PROMETHEUS_SCRAPE        "Enable Promeheus Scrape input plugin"         Yes)
option(FLB_IN_STATSD                   "Enable StatsD input plugin"                   Yes)
option(FLB_IN_EVENT_TEST               "Enable event test plugin"                      No)
option(FLB_IN_STORAGE_BACKLOG          "Enable storage backlog input plugin"          Yes)
option(FLB_IN_EMITTER                  "Enable emitter input plugin"                  Yes)
option(FLB_IN_NODE_EXPORTER_METRICS    "Enable node exporter metrics input plugin"    Yes)
option(FLB_IN_WINDOWS_EXPORTER_METRICS "Enable windows exporter metrics input plugin" Yes)
option(FLB_IN_PODMAN_METRICS           "Enable Podman Metrics input plugin"           Yes)
option(FLB_IN_OPENTELEMETRY            "Enable OpenTelemetry input plugin"            Yes)
option(FLB_IN_ELASTICSEARCH            "Enable Elasticsearch (Bulk API) input plugin" Yes)
option(FLB_IN_CALYPTIA_FLEET           "Enable Calyptia Fleet input plugin"           Yes)
option(FLB_IN_SPLUNK                   "Enable Splunk HTTP HEC input plugin"          Yes)
option(FLB_OUT_AZURE                   "Enable Azure output plugin"                   Yes)
option(FLB_OUT_AZURE_BLOB              "Enable Azure output plugin"                   Yes)
option(FLB_OUT_AZURE_LOGS_INGESTION    "Enable Azure Logs Ingestion output plugin"    Yes)
option(FLB_OUT_AZURE_KUSTO             "Enable Azure Kusto output plugin"             Yes)
option(FLB_OUT_BIGQUERY                "Enable BigQuery output plugin"                Yes)
option(FLB_OUT_CALYPTIA                "Enable Calyptia monitoring plugin"            Yes)
option(FLB_OUT_COUNTER                 "Enable Counter output plugin"                 Yes)
option(FLB_OUT_DATADOG                 "Enable DataDog output plugin"                 Yes)
option(FLB_OUT_ES                      "Enable Elasticsearch output plugin"           Yes)
option(FLB_OUT_EXIT                    "Enable Exit output plugin"                    Yes)
option(FLB_OUT_FORWARD                 "Enable Forward output plugin"                 Yes)
option(FLB_OUT_GELF                    "Enable GELF output plugin"                    Yes)
option(FLB_OUT_HTTP                    "Enable HTTP output plugin"                    Yes)
option(FLB_OUT_INFLUXDB                "Enable InfluxDB output plugin"                Yes)
option(FLB_OUT_NATS                    "Enable NATS output plugin"                    Yes)
option(FLB_OUT_NRLOGS                  "Enable New Relic output plugin"               Yes)
option(FLB_OUT_OPENSEARCH              "Enable OpenSearch output plugin"              Yes)
option(FLB_OUT_TCP                     "Enable TCP output plugin"                     Yes)
option(FLB_OUT_UDP                     "Enable UDP output plugin"                     Yes)
option(FLB_OUT_PLOT                    "Enable Plot output plugin"                    Yes)
option(FLB_OUT_FILE                    "Enable file output plugin"                    Yes)
option(FLB_OUT_TD                      "Enable Treasure Data output plugin"           Yes)
option(FLB_OUT_RETRY                   "Enable Retry test output plugin"               No)
option(FLB_OUT_PGSQL                   "Enable PostgreSQL output plugin"               No)
option(FLB_OUT_SKYWALKING              "Enable Apache SkyWalking output plugin"       Yes)
option(FLB_OUT_SLACK                   "Enable Slack output plugin"                   Yes)
option(FLB_OUT_SPLUNK                  "Enable Splunk output plugin"                  Yes)
option(FLB_OUT_STACKDRIVER             "Enable Stackdriver output plugin"             Yes)
option(FLB_OUT_STDOUT                  "Enable STDOUT output plugin"                  Yes)
option(FLB_OUT_SYSLOG                  "Enable Syslog output plugin"                  Yes)
option(FLB_OUT_LIB                     "Enable library mode output plugin"            Yes)
option(FLB_OUT_NULL                    "Enable dev null output plugin"                Yes)
option(FLB_OUT_FLOWCOUNTER             "Enable flowcount output plugin"               Yes)
option(FLB_OUT_LOGDNA                  "Enable LogDNA output plugin"                  Yes)
option(FLB_OUT_LOKI                    "Enable Loki output plugin"                    Yes)
option(FLB_OUT_KAFKA                   "Enable Kafka output plugin"                   Yes)
option(FLB_OUT_KAFKA_REST              "Enable Kafka Rest output plugin"              Yes)
option(FLB_OUT_CLOUDWATCH_LOGS         "Enable AWS CloudWatch output plugin"          Yes)
option(FLB_OUT_KINESIS_FIREHOSE        "Enable AWS Firehose output plugin"            Yes)
option(FLB_OUT_KINESIS_STREAMS         "Enable AWS Kinesis output plugin"             Yes)
option(FLB_OUT_OPENTELEMETRY           "Enable OpenTelemetry plugin"                  Yes)
option(FLB_OUT_PROMETHEUS_EXPORTER     "Enable Prometheus exporter plugin"            Yes)
option(FLB_OUT_PROMETHEUS_REMOTE_WRITE "Enable Prometheus remote write plugin"        Yes)
option(FLB_OUT_S3                      "Enable AWS S3 output plugin"                  Yes)
option(FLB_OUT_VIVO_EXPORTER           "Enabel Vivo exporter output plugin"           Yes)
option(FLB_OUT_WEBSOCKET               "Enable Websocket output plugin"               Yes)
option(FLB_OUT_ORACLE_LOG_ANALYTICS    "Enable Oracle Cloud Infrastructure Logging analytics plugin"          Yes)
option(FLB_OUT_CHRONICLE               "Enable Google Chronicle output plugin"        Yes)
option(FLB_FILTER_ALTER_SIZE           "Enable alter_size filter"                     Yes)
option(FLB_FILTER_AWS                  "Enable aws filter"                            Yes)
option(FLB_FILTER_ECS                  "Enable AWS ECS filter"                        Yes)
option(FLB_FILTER_CHECKLIST            "Enable checklist filter"                      Yes)
option(FLB_FILTER_EXPECT               "Enable expect filter"                         Yes)
option(FLB_FILTER_GREP                 "Enable grep filter"                           Yes)
option(FLB_FILTER_MODIFY               "Enable modify filter"                         Yes)
option(FLB_FILTER_STDOUT               "Enable stdout filter"                         Yes)
option(FLB_FILTER_PARSER               "Enable parser filter"                         Yes)
option(FLB_FILTER_KUBERNETES           "Enable kubernetes filter"                     Yes)
option(FLB_FILTER_REWRITE_TAG          "Enable tag rewrite filter"                    Yes)
option(FLB_FILTER_THROTTLE             "Enable throttle filter"                       Yes)
option(FLB_FILTER_THROTTLE_SIZE        "Enable throttle size filter"                   No)
option(FLB_FILTER_TYPE_CONVERTER       "Enable type converter filter"                 Yes)
option(FLB_FILTER_MULTILINE            "Enable multiline filter"                      Yes)
option(FLB_FILTER_NEST                 "Enable nest filter"                           Yes)
option(FLB_FILTER_LOG_TO_METRICS       "Enable log-derived metrics filter"            Yes)
option(FLB_FILTER_LUA                  "Enable Lua scripting filter"                  Yes)
option(FLB_FILTER_LUA_USE_MPACK        "Enable mpack on the lua filter"                No)
option(FLB_FILTER_RECORD_MODIFIER      "Enable record_modifier filter"                Yes)
option(FLB_FILTER_TENSORFLOW           "Enable tensorflow filter"                      No)
option(FLB_FILTER_GEOIP2               "Enable geoip2 filter"                         Yes)
option(FLB_FILTER_NIGHTFALL            "Enable Nightfall filter"                      Yes)
option(FLB_FILTER_WASM                 "Enable WASM filter"                           Yes)
option(FLB_PROCESSOR_LABELS            "Enable metrics label manipulation processor"  Yes)
option(FLB_PROCESSOR_ATTRIBUTES        "Enable atributes manipulation processor"      Yes)

if(DEFINED FLB_NIGHTLY_BUILD AND NOT "${FLB_NIGHTLY_BUILD}" STREQUAL "")
  FLB_DEFINITION_VAL(FLB_NIGHTLY_BUILD ${FLB_NIGHTLY_BUILD})
endif()

if(FLB_IN_STORAGE_BACKLOG)
  FLB_DEFINITION(FLB_HAVE_IN_STORAGE_BACKLOG)
endif()

# Debug callbacks
option(FLB_HTTP_CLIENT_DEBUG  "Enable HTTP Client debug callbacks"   No)

# Run ldconfig on package post-install
option(FLB_RUN_LDCONFIG "Enable execution of ldconfig after installation" No)

# Enable all features
if(FLB_ALL)
  # Global
  set(FLB_DEBUG           1)
  set(FLB_TLS             1)

  # Input plugins
  set(FLB_IN_CPU          1)
  set(FLB_IN_MEM          1)
  set(FLB_IN_KMSG         1)
  set(FLB_IN_MQTT         1)
  set(FLB_IN_SERIAL       1)
  set(FLB_IN_STDIN        1)
  set(FLB_IN_HEAD         1)
  set(FLB_IN_PROC         1)
  set(FLB_IN_DISK         1)
  set(FLB_IN_DUMMY        1)
  set(FLB_IN_DUMMY_THREAD 1)
  set(FLB_IN_NETIF        1)
  set(FLB_IN_NGINX_STATUS 1)
  set(FLB_IN_EXEC         1)
  set(FLB_IN_UNIX_SOCKET  1)

  # Output plugins
  set(FLB_OUT_ES          1)
  set(FLB_OUT_FORWARD     1)
  set(FLB_OUT_GELF        1)
  set(FLB_OUT_HTTP        1)
  set(FLB_OUT_NATS        1)
  set(FLB_OUT_NULL        1)
  set(FLB_OUT_PLOT        1)
  set(FLB_OUT_FILE        1)
  set(FLB_OUT_RETRY       1)
  set(FLB_OUT_TD          1)
  set(FLB_OUT_STDOUT      1)
  set(FLB_OUT_S3          1)
  set(FLB_OUT_SYSLOG      1)
  set(FLB_OUT_LIB         1)
  set(FLB_OUT_FLOWCOUNTER 1)
  set(FLB_OUT_WEBSOCKET   1)
endif()

if(FLB_DEV)
  set(FLB_DEBUG             On)
  set(FLB_TRACE             On)
  set(FLB_CHUNK_TRACE       On)
  set(FLB_METRICS           On)
  set(FLB_IN_EVENT_TEST     On)
  set(FLB_HTTP_SERVER       On)
  set(FLB_HTTP_CLIENT_DEBUG On)
  set(FLB_TESTS_INTERNAL    On)
endif()

if(FLB_TRACE)
  add_definitions(-DFLB_TRACE=1)
endif()

if(FLB_CHUNK_TRACE)
  FLB_DEFINITION(FLB_HAVE_CHUNK_TRACE)
endif()

# SSL/TLS: add encryption support
if(FLB_OUT_TD)
  set(FLB_TLS ON)
endif()

if(FLB_HTTP_CLIENT_DEBUG)
  FLB_DEFINITION(FLB_HAVE_HTTP_CLIENT_DEBUG)
endif()

if (FLB_TESTS_OSSFUZZ)
  FLB_DEFINITION(FLB_HAVE_TESTS_OSSFUZZ)
endif()

if (FLB_WASM)
  # For Linking libedit adjustments on LLVM 15.
  include(cmake/FindLibEdit.cmake)
endif()

# Set Fluent Bit dependency libraries path
include(cmake/libraries.cmake)

# Export headers provided by libraries/dependencies
include(cmake/headers.cmake)

# Tweak build targets for Windows
if(FLB_SYSTEM_WINDOWS)
  include(cmake/windows-setup.cmake)
endif()

# Tweak build targets for macOS
if (FLB_SYSTEM_MACOS)
  # build tweaks
  include(cmake/macos-setup.cmake)
endif()

# Build for SystemZ - s390x arch
if (FLB_SYSTEM_LINUX)
  include(cmake/s390x.cmake)
endif ()

# Extract Git commit information for debug output.
# Note that this is only set when cmake is run, the intent here is to use in CI for verification of releases so is acceptable.
# For a better solution see https://jonathanhamberg.com/post/cmake-embedding-git-hash/ but this is simple and easy.
find_package(Git)
# If we do not have Git or this is not a Git repo or another error this just is ignored and we have no output at runtime.
execute_process(COMMAND
  "${GIT_EXECUTABLE}" log -1 --format=%H
  WORKING_DIRECTORY "${FLB_ROOT}"
  OUTPUT_VARIABLE FLB_GIT_HASH
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "Git hash: ${FLB_GIT_HASH}")

# Optional features like Stream Processor and Record Accessor needs Flex
# and Bison to generate it parsers.
find_package(FLEX 2)
find_package(BISON 3)

if(FLEX_FOUND AND BISON_FOUND)
  set(FLB_FLEX_BISON  1)
endif()

if(FLB_SMALL)
  if(CMAKE_COMPILER_IS_GNUCC)
    set(strip_flag  " -s ")
  else()
    set(strip_flag  "")
  endif()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -g0 ${strip_flag} -fno-stack-protector -fomit-frame-pointer -DNDEBUG -U_FORTIFY_SOURCE")
endif()

if(FLB_COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# Enable Debug symbols if specified
if(MSVC)
  set(CMAKE_BUILD_TYPE None)  # Avoid flag conflicts (See CMakeList.txt:L18)
elseif(FLB_DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
elseif(FLB_RELEASE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

if(FLB_IPO STREQUAL "On" OR (FLB_IPO STREQUAL "ReleaseOnly" AND FLB_RELEASE))
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported)
  # IPO in GCC versions smaller v8 is broken
  if(ipo_supported AND NOT (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8))
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(Warning "IPO is not supported on this platform")
  endif()
endif()

if(FLB_PARSER)
  FLB_DEFINITION(FLB_HAVE_PARSER)
  message(STATUS "Enabling FLB_REGEX since FLB_PARSER requires")
  set(FLB_REGEX On)
endif()

# Is sanitize_address defined ?
if(SANITIZE_ADDRESS)
  FLB_DEFINITION(FLB_HAVE_SANITIZE_ADDRESS)
endif()

# Record Accessor
if(FLB_RECORD_ACCESSOR)
  if(NOT FLB_FLEX_BISON)
    message(FATAL_ERROR
      "Record Accessor feature requires Flex and Bison in your system.\n"
      "This is a build time dependency, you can either install the "
      "dependencies or disable the feature setting the CMake option "
      "-DFLB_RECORD_ACCESSOR=Off ."
      )
  endif()
  FLB_DEFINITION(FLB_HAVE_RECORD_ACCESSOR)
endif()

# Stream Processor
if(FLB_STREAM_PROCESSOR)
  if(NOT FLB_FLEX_BISON)
    message(FATAL_ERROR
      "Stream Processor feature requires Flex and Bison in your system.\n"
      "This is a build time dependency, you can either install the "
      "dependencies or disable the feature setting the CMake option "
      "-DFLB_STREAM_PROCESSOR=Off ."
      )
  endif()

  # Enable Stream Processor internal helper plugin
  set(FLB_IN_STREAM_PROCESSOR On)
  FLB_DEFINITION(FLB_HAVE_STREAM_PROCESSOR)
endif()

# mk_core is aware about jemalloc usage, we need to disable this as
# fluent-bit do not use it.
set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")

# Headers: required headers by bundled libraries, this act as a helper for
# CFL, Ctraces, CMetrics and fluent-otel-proto
#
# Note: any check_c_source_compiles() cmake function might require this to
# work.
#
set(CMAKE_REQUIRED_INCLUDES
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CFL}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_FLUENT_OTEL}/include/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_FLUENT_OTEL}/proto_c/
  )

# CFL
add_subdirectory(${FLB_PATH_LIB_CFL} EXCLUDE_FROM_ALL)

# fluent-otel-proto
FLB_OPTION(FLUENT_PROTO_METRICS ON)
add_subdirectory(${FLB_PATH_LIB_FLUENT_OTEL} EXCLUDE_FROM_ALL)

# MsgPack options
option(MSGPACK_ENABLE_CXX             OFF)
option(MSGPACK_ENABLE_SHARED          OFF)
option(MSGPACK_BUILD_TESTS            OFF)
option(MSGPACK_BUILD_EXAMPLES         OFF)
add_subdirectory(${FLB_PATH_LIB_MSGPACK} EXCLUDE_FROM_ALL)

# MPack
add_definitions(-DMPACK_EXTENSIONS=1)
add_subdirectory(${FLB_PATH_LIB_MPACK} EXCLUDE_FROM_ALL)

# Miniz (zip)
add_subdirectory(${FLB_PATH_LIB_MINIZ} EXCLUDE_FROM_ALL)

# ring buffer library
add_subdirectory(${FLB_PATH_LIB_RING_BUFFER} EXCLUDE_FROM_ALL)

# Avro
if(FLB_AVRO_ENCODER)
  # jansson
  option(JANSSON_BUILD_DOCS         OFF)
  option(JANSSON_EXAMPLES           OFF)
  option(JANSSON_WITHOUT_TESTS       ON)
  option(JANSSON_BUILD_SHARED_LIBS  OFF)
  add_subdirectory(${FLB_PATH_LIB_JANSSON})

  #avro
  add_subdirectory(${FLB_PATH_LIB_AVRO} EXCLUDE_FROM_ALL)
endif()

# tutf8e
if(FLB_UTF8_ENCODER)
  add_subdirectory(${FLB_PATH_LIB_TUTF8E} EXCLUDE_FROM_ALL)
endif()

# snappy
add_subdirectory(${FLB_PATH_LIB_SNAPPY} EXCLUDE_FROM_ALL)

# CMetrics
add_subdirectory(${FLB_PATH_LIB_CMETRICS} EXCLUDE_FROM_ALL)

# CTraces
add_subdirectory(${FLB_PATH_LIB_CTRACES} EXCLUDE_FROM_ALL)

# C-Ares (DNS library)
FLB_OPTION(CARES_STATIC      ON)
FLB_OPTION(CARES_SHARED      OFF)
FLB_OPTION(CARES_INSTALL     OFF)
FLB_OPTION(CARES_BUILD_TESTS OFF)
FLB_OPTION(CARES_BUILD_TOOLS OFF)
if (FLB_SYSTEM_MACOS)
  # macOS SDK always has <arpa/nameser.h>.
  FLB_DEFINITION(CARES_HAVE_ARPA_NAMESER_H)
endif()
add_subdirectory(${FLB_PATH_LIB_CARES})# EXCLUDE_FROM_ALL)

# Chunk I/O
FLB_OPTION(CIO_LIB_STATIC  ON)
FLB_OPTION(CIO_LIB_SHARED  OFF)
add_subdirectory(${FLB_PATH_LIB_CHUNKIO} EXCLUDE_FROM_ALL)

# Lib: build the core libraries used by Fluent-Bit
FLB_DEFINITION(JSMN_PARENT_LINKS)
FLB_DEFINITION(JSMN_STRICT)
add_subdirectory(${FLB_PATH_LIB_JSMN})
# Runtime Tests (filter_kubernetes) requires HTTP Server
if(FLB_TESTS_RUNTIME)
  FLB_OPTION(FLB_HTTP_SERVER  ON)
endif()

# MK Core
macro(MK_SET_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
MK_SET_OPTION(MK_SYSTEM_MALLOC  ON)
MK_SET_OPTION(MK_DEBUG          ON)

# Build Monkey HTTP Server
if(FLB_HTTP_SERVER)
  add_subdirectory(${FLB_PATH_LIB_MONKEY} EXCLUDE_FROM_ALL)
else()
  add_subdirectory(${FLB_PATH_LIB_MONKEY}/mk_core EXCLUDE_FROM_ALL)
endif()

if(FLB_TLS)
  FLB_DEFINITION(FLB_HAVE_TLS)

  option(ENABLE_TESTING  OFF)
  option(ENABLE_PROGRAMS OFF)
  option(INSTALL_MBEDTLS_HEADERS OFF)

  # Link OpenSSL statically on Windows.
  if (FLB_SYSTEM_WINDOWS)
    set(OPENSSL_USE_STATIC_LIBS ON)
    set(OPENSSL_MSVC_STATIC_RT  ON)
  endif()

  # find OpenSSL (our preferred choice now)
  find_package(OpenSSL)
  if(OPENSSL_FOUND)
    FLB_DEFINITION(FLB_HAVE_OPENSSL)
  endif()
endif()

# Metrics
if(FLB_METRICS)
  FLB_DEFINITION(FLB_HAVE_METRICS)
endif()

# WASM
if(FLB_WASM)
  if (FLB_SYSTEM_LINUX)
    check_c_source_compiles("
       #include <stdatomic.h>
       int main() {
          _Atomic int a;
          return 0;
       }" FLB_HAVE_STDATOMIC_H)
    check_include_files(stdatomic.h FLB_HAVE_STDATOMIC_H)
    if (FLB_HAVE_STDATOMIC_H)
      enable_language (ASM)
      FLB_DEFINITION(FLB_HAVE_WASM)
    else ()
      message(STATUS "This platform does not provide stdatomic.h that is needed for the FLB_WASM feature so disabled.")
      set(FLB_WASM OFF)
    endif ()
  else ()
    enable_language (ASM)
    FLB_DEFINITION(FLB_HAVE_WASM)
  endif ()
endif()

# AWS
if (FLB_AWS)
  FLB_DEFINITION(FLB_HAVE_AWS)

  # Support for credential_process in the AWS config file is currently Linux-only.
  # The current implementation might work for other Unix systems, but would require
  # further testing to confirm.
  # Spawning a sub-process in Windows is very different and will require its own
  # implementation.
  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FLB_OPTION(FLB_HAVE_AWS_CREDENTIAL_PROCESS ON)
    FLB_DEFINITION(FLB_HAVE_AWS_CREDENTIAL_PROCESS)
  else()
    FLB_OPTION(FLB_HAVE_AWS_CREDENTIAL_PROCESS OFF)
  endif()
endif()

if (FLB_AWS_ERROR_REPORTER)
  FLB_DEFINITION(FLB_HAVE_AWS_ERROR_REPORTER)
endif()

# Signv4
if (FLB_SIGNV4)
  FLB_DEFINITION(FLB_HAVE_SIGNV4)
endif()

if(FLB_SQLDB)
  FLB_DEFINITION(FLB_HAVE_SQLDB)
  add_subdirectory(${FLB_PATH_LIB_SQLITE})
endif()

if(FLB_TRACE)
  FLB_DEFINITION(FLB_HAVE_TRACE)
endif()

# Disable colors and any other control characters in the output
if (FLB_LOG_NO_CONTROL_CHARS)
  FLB_DEFINITION(FLB_LOG_NO_CONTROL_CHARS)
endif()

if(FLB_HTTP_SERVER)
  FLB_OPTION(FLB_METRICS ON)
  FLB_DEFINITION(FLB_HAVE_METRICS)
  FLB_DEFINITION(FLB_HAVE_HTTP_SERVER)
endif()

if(NOT TARGET co)
  add_subdirectory(${FLB_PATH_LIB_CO})
endif()

if(NOT TARGET rbtree)
  add_subdirectory(${FLB_PATH_LIB_RBTREE})
endif()

# Systemd Journald support
if(JOURNALD_FOUND)
  FLB_DEFINITION(FLB_HAVE_SYSTEMD)

  check_c_source_compiles("
    #include <systemd/sd-bus.h>
    int main() {
       return 0;
    }" FLB_HAVE_SYSTEMD_SDBUS)

  if(FLB_HAVE_SYSTEMD_SDBUS)
    FLB_DEFINITION(FLB_HAVE_SYSTEMD_SDBUS)
  endif()
else()
  FLB_OPTION(FLB_IN_SYSTEMD OFF)
endif()

# Valgrind support
check_c_source_compiles("
  #include <valgrind/valgrind.h>
  int main() {
     return 0;
  }" FLB_HAVE_VALGRIND)

if(FLB_VALGRIND OR FLB_HAVE_VALGRIND)
  FLB_DEFINITION(FLB_HAVE_VALGRIND)
endif()

# fork(2) support
check_c_source_compiles("
  #include <unistd.h>
  int main() {
     fork();
     return 0;
  }" FLB_HAVE_FORK)

if(FLB_HAVE_FORK)
  FLB_DEFINITION(FLB_HAVE_FORK)
endif()

# mtrace support
if(FLB_MTRACE)
  check_c_source_compiles("
    #include <mcheck.h>
    int main() {
       return 0;
    }" FLB_HAVE_MTRACE)

  if(FLB_HAVE_MTRACE AND FLB_DEBUG)
    FLB_DEFINITION(FLB_HAVE_MTRACE)
  endif()
endif()

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" FLB_HAVE_TIMESPEC_GET)
if(FLB_HAVE_TIMESPEC_GET)
  FLB_DEFINITION(FLB_HAVE_TIMESPEC_GET)
endif()

# gmtoff support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     tm.tm_gmtoff = 0;
     return 0;
  }" FLB_HAVE_GMTOFF)
if(FLB_HAVE_GMTOFF)
  FLB_DEFINITION(FLB_HAVE_GMTOFF)
endif()

# clock_get_time() support for macOS.
check_c_source_compiles("
  #include <mach/clock.h>
  #include <mach/mach.h>
  int main() {
      clock_serv_t cclock;
      mach_timespec_t mts;
      host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
      clock_get_time(cclock, &mts);
      return mach_port_deallocate(mach_task_self(), cclock);
  }" FLB_HAVE_CLOCK_GET_TIME)
if(FLB_HAVE_CLOCK_GET_TIME)
  FLB_DEFINITION(FLB_HAVE_CLOCK_GET_TIME)
endif()

# unix socket support
check_c_source_compiles("
  #include <unistd.h>
  #include <sys/un.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  int main() {
      int sock;
      sock = socket(AF_UNIX, SOCK_STREAM, 0);
      close(sock);
      return 0;
  }" FLB_HAVE_UNIX_SOCKET)
if(FLB_HAVE_UNIX_SOCKET)
  FLB_DEFINITION(FLB_HAVE_UNIX_SOCKET)
endif()

# Configuration file YAML format support
if(FLB_CONFIG_YAML)
  find_package(PkgConfig)
  # libyaml's corresponding pkg-config file is yaml-0.1.pc.
  # We should search it first.
  pkg_check_modules(LIBYAML QUIET yaml-0.1)

  if (LIBYAML_FOUND)
    # For if(FLB_HAVE_LIBYAML) clause on CMakeList.txt.
    set(FLB_HAVE_LIBYAML 1)
    FLB_DEFINITION(FLB_HAVE_LIBYAML)
    # For non-standard libyaml installation paths such as homebrew bottled libyaml.
    include_directories(${LIBYAML_INCLUDEDIR})
    link_directories(${LIBYAML_LIBRARY_DIRS})
  else()
    if (FLB_LIBYAML_DIR)
      set(LIBYAML_LIBRARY_DIRS "${FLB_LIBYAML_DIR}/lib")
      set(LIBYAML_INCLUDEDIR "${FLB_LIBYAML_DIR}/include")
      message(STATUS "specified libyaml dir: ${FLB_LIBYAML_DIR}")
      if (MSVC)
        FLB_DEFINITION(YAML_DECLARE_STATIC)
      endif ()
      set(FLB_HAVE_LIBYAML 1)
      FLB_DEFINITION(FLB_HAVE_LIBYAML)
      include_directories(${LIBYAML_INCLUDEDIR})
      link_directories(${LIBYAML_LIBRARY_DIRS})
    else ()
      # Requires libyaml support
      check_c_source_compiles("
      #include <yaml.h>
      int main() {
        yaml_parser_t parser;
        return 0;
      }" FLB_HAVE_LIBYAML)

      if(NOT FLB_HAVE_LIBYAML)
        message(FATAL_ERROR
          "YAML development dependencies required for YAML configuration format handling.\n"
          "This is a build time dependency, you can either install the "
          "dependencies or disable the feature setting the CMake option "
          "-DFLB_CONFIG_YAML=Off ."
        )
      endif()
    endif ()

    FLB_DEFINITION(FLB_HAVE_LIBYAML)
  endif()
endif()

# check attribute alloc_size
check_c_source_compiles("
#include <stdlib.h>
__attribute__ ((alloc_size(1, 2))) static void* f(size_t a, size_t b) {
    return calloc(a, b);
}
int main() {
    f(1, 2);
    return 0;
}
" FLB_HAVE_ATTRIBUTE_ALLOC_SIZE)
if(FLB_HAVE_ATTRIBUTE_ALLOC_SIZE)
  FLB_DEFINITION(FLB_HAVE_ATTRIBUTE_ALLOC_SIZE)
endif()

# parameters for flb_msgpack_raw_to_json_sds buffer strategy
if (NOT DEFINED FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE)
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE 2.0)
else()
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE ${FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE})
endif()

if (NOT DEFINED FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE)
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE 0.10)
else()
  FLB_DEFINITION_VAL(FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE ${FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE})
endif()

# Build tools/xxd-c
add_subdirectory(tools/xxd-c)

# Static configuration generator (using xxd-c)
if(FLB_STATIC_CONF)
  FLB_DEFINITION(FLB_HAVE_STATIC_CONF)
  add_subdirectory(gen_static_conf)
endif()

# Special definition to set the coroutine stack size
if(FLB_CORO_STACK_SIZE)
  add_definitions(-DFLB_CORO_STACK_SIZE=${FLB_CORO_STACK_SIZE})
  set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef FLB_CORO_STACK_SIZE\n#define FLB_CORO_STACK_SIZE ${FLB_CORO_STACK_SIZE}\n#endif\n")
else()

endif()

set(FLB_PROG_NAME "Fluent Bit")
set(FLB_OUT_NAME "fluent-bit")

if(FLB_PROXY_GO)
  FLB_DEFINITION(FLB_HAVE_PROXY_GO)
endif()

if("${GNU_HOST}" STREQUAL "")
    set(AUTOCONF_HOST_OPT "")
else()
    set(AUTOCONF_HOST_OPT "--host=${GNU_HOST}")
endif()

# Memory Allocator
# ================
if(FLB_JEMALLOC AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  FLB_DEFINITION(FLB_HAVE_JEMALLOC)
  FLB_DEFINITION(JEMALLOC_MANGLE)

  # Add support for options like page size, if empty we default it
  if(NOT DEFINED FLB_JEMALLOC_OPTIONS OR "${FLB_JEMALLOC_OPTIONS}" STREQUAL "")
    set(FLB_JEMALLOC_OPTIONS "--with-lg-quantum=3")
  endif()
  # Split into a list so CMake handles it correctly when passing to configure command
  separate_arguments(FLB_JEMALLOC_OPTIONS_LIST UNIX_COMMAND ${FLB_JEMALLOC_OPTIONS})
  message(STATUS "jemalloc configure: ${FLB_JEMALLOC_OPTIONS_LIST}")

  # Link to Jemalloc as an external dependency
  ExternalProject_Add(jemalloc
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/jemalloc-5.3.0
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/jemalloc-5.3.0/configure ${AUTOCONF_HOST_OPT} "${FLB_JEMALLOC_OPTIONS_LIST}" --prefix=<INSTALL_DIR>
    CFLAGS=-std=gnu99\ -Wall\ -pipe\ -g3\ -O3\ -funroll-loops
    BUILD_COMMAND $(MAKE)
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/
    INSTALL_COMMAND $(MAKE) install_lib_static install_include)
  add_library(libjemalloc STATIC IMPORTED GLOBAL)
  set_target_properties(libjemalloc PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/lib/libjemalloc_pic.a")
  add_dependencies(libjemalloc jemalloc)
  include_directories("${CMAKE_BINARY_DIR}/include/")
else()
  FLB_OPTION(FLB_JEMALLOC OFF)
endif()

# LibBacktrace (friendly stacktrace support)
# =========================================
if(FLB_BACKTRACE)
  FLB_DEFINITION(FLB_HAVE_LIBBACKTRACE)
  if (CMAKE_OSX_SYSROOT)
    # From macOS Mojave, /usr/include does not store C SDK headers.
    # For libbacktrace building on macOS, we have to tell C headers where they are located.
    set(DEPS_C_COMPILER "${CMAKE_C_COMPILER} -isysroot ${CMAKE_OSX_SYSROOT}")
  else()
    set(DEPS_C_COMPILER "${CMAKE_C_COMPILER}")
  endif()
  ExternalProject_Add(backtrace
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbacktrace-8602fda/
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbacktrace-8602fda/configure ${AUTOCONF_HOST_OPT} --prefix=<INSTALL_DIR> --enable-shared=no --enable-static=yes
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND $(MAKE) DESTDIR= install
    )
  add_library(libbacktrace STATIC IMPORTED GLOBAL)
  set_target_properties(libbacktrace PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/lib/libbacktrace.a")
  add_dependencies(libbacktrace backtrace)
  include_directories("${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/include/")
endif()

if(FLB_IN_KAFKA OR FLB_OUT_KAFKA)
    FLB_OPTION(RDKAFKA_BUILD_STATIC    On)
    FLB_OPTION(RDKAFKA_BUILD_EXAMPLES Off)
    FLB_OPTION(RDKAFKA_BUILD_TESTS    Off)
    FLB_OPTION(ENABLE_LZ4_EXT         Off)

    # disable Curl
    if (FLB_SYSTEM_MACOS)
      FLB_OPTION(WITH_CURL  Off)
    endif()

    add_subdirectory(${FLB_PATH_LIB_RDKAFKA} EXCLUDE_FROM_ALL)
endif()

# Onigmo (Regex Engine) options
# =====================
if(FLB_REGEX)
  option(ONIGMO_SHARED_LIB    OFF)
  option(ONIGMO_CTESTS        OFF)
  option(ONIGMO_CTESTS_SAMPLE OFF)
  option(ONIGMO_PYTHON_TESTS  OFF)
  FLB_DEFINITION(FLB_HAVE_REGEX)

  if (FLB_SYSTEM_WINDOWS)
    # We need this line in order to link libonigmo.lib statically.
    # Read onigmo/README for details.
    FLB_DEFINITION_VAL(ONIG_EXTERN "extern")
  endif()
  add_subdirectory(${FLB_PATH_LIB_ONIGMO} EXCLUDE_FROM_ALL)
endif()

# tutf8e (UTF8 Encoding)
# =====================
if(FLB_UTF8_ENCODER)
  FLB_DEFINITION(FLB_HAVE_UTF8_ENCODER)
endif()

# avro-c (Avro Encoding)
# =====================
if(FLB_AVRO_ENCODER)
  FLB_DEFINITION(FLB_HAVE_AVRO_ENCODER)
endif()

# LuaJIT (Scripting Support)
# ==========================
if(FLB_LUAJIT)
  include(cmake/luajit.cmake)
  FLB_DEFINITION(FLB_HAVE_LUAJIT)
endif()

# PostgreSQL
# ==========
find_package(PostgreSQL)
if(FLB_OUT_PGSQL AND (NOT PostgreSQL_FOUND))
   FLB_OPTION(FLB_OUT_PGSQL OFF)
endif()

# Arrow GLib
# ==========
find_package(PkgConfig)
pkg_check_modules(ARROW_GLIB QUIET arrow-glib)
if(FLB_ARROW AND ARROW_GLIB_FOUND)
  FLB_DEFINITION(FLB_HAVE_ARROW)
else()
  set(FLB_ARROW OFF)
endif()

# Pthread Local Storage
# =====================
# By default we expect the compiler already support thread local storage
# through __thread type, otherwise Fluent Bit fallback to the old POSIX
# pthread mode (pthread_key_t), or it can be forced setting FLB_POSIX_TLS
# for testing/compatibility purposes.
if(NOT FLB_POSIX_TLS)
  check_c_source_compiles("
   __thread int a;
   int main() {
       __tls_get_addr(0);
       return 0;
   }" FLB_HAVE_C_TLS)
  if(FLB_HAVE_C_TLS)
    FLB_DEFINITION(FLB_HAVE_C_TLS)
  endif()
endif()

# accept(4)
check_c_source_compiles("
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <sys/socket.h>
    int main() {
        accept4(0, NULL, NULL, 0);
        return 0;
    }" FLB_HAVE_ACCEPT4)
if(FLB_HAVE_ACCEPT4)
  FLB_DEFINITION(FLB_HAVE_ACCEPT4)
endif()

# inotify_init(2)
if(FLB_INOTIFY)
  check_c_source_compiles("
    #include <sys/inotify.h>
    int main() {
        return inotify_init1(0);
    }" FLB_HAVE_INOTIFY)
  if(FLB_HAVE_INOTIFY)
    FLB_DEFINITION(FLB_HAVE_INOTIFY)
  endif()
endif()

include(CheckSymbolExists)

# Check for getentropy(3)
check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
if(HAVE_GETENTROPY)
  FLB_DEFINITION(FLB_HAVE_GETENTROPY)
endif()

# getentropy(3) is in sys/random.h on mac
check_symbol_exists(getentropy "sys/random.h" HAVE_GETENTROPY_SYS_RANDOM)
if(HAVE_GETENTROPY_SYS_RANDOM)
  FLB_DEFINITION(FLB_HAVE_GETENTROPY_SYS_RANDOM)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/tls/flb_tls_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/tls/flb_tls_info.h"
  )

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(FLB_INSTALL_BINDIR "bin")
  set(FLB_INSTALL_LIBDIR "lib")
  set(FLB_INSTALL_CONFDIR "conf")
  set(FLB_INSTALL_INCLUDEDIR "include")
else()
  set(FLB_INSTALL_BINDIR ${CMAKE_INSTALL_FULL_BINDIR})
  set(FLB_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}/${FLB_OUT_NAME}")
  set(FLB_INSTALL_CONFDIR "${CMAKE_INSTALL_SYSCONFDIR}/${FLB_OUT_NAME}/")
  set(FLB_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(include)
add_subdirectory(plugins)
add_subdirectory(src)

if(NOT FLB_SHARED_LIB)
  set(FLB_EXAMPLES OFF)
endif()

if(FLB_EXAMPLES)
  add_subdirectory(examples)
endif()

if(FLB_TESTS_RUNTIME)
  enable_testing()
  add_subdirectory(tests/runtime/)
  add_subdirectory(tests/runtime_shell/)
endif()

if(FLB_TESTS_INTERNAL)
  enable_testing()
  add_subdirectory(tests/internal/)
endif()

# Installer Generation (Cpack)
# ============================

set(CPACK_PACKAGE_VERSION ${FLB_VERSION_STR})
set(CPACK_PACKAGE_NAME "fluent-bit")

set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo@calyptia.com>")
set(CPACK_PACKAGE_VENDOR "Calyptia Inc.")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

if(FLB_SYSTEM_WINDOWS)
  set(CPACK_GENERATOR "NSIS" "ZIP" "WIX")

  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|AARCH64)")
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-winarm64")
  elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win64")
  else()
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32")
  endif()
endif()

# Enable components
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_productbuild_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL ${CPACK_COMPONENTS_ALL} binary library headers headers-extra)
set(CPACK_COMPONENTS_GROUPING "ONE_PER_GROUP")

set(CPACK_COMPONENT_BINARY_GROUP "RUNTIME")
set(CPACK_COMPONENT_LIBRARY_GROUP "RUNTIME")

# Debian package setup and name sanitizer
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

find_program(DPKG_PROGRAM dpkg DOC "dpkg program of Debian-based systems")
if(DPKG_PROGRAM)
  execute_process(
    COMMAND ${DPKG_PROGRAM} --print-architecture
    OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

  set(CPACK_DEBIAN_HEADERS_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-headers.deb")
  set(CPACK_DEBIAN_HEADERS_EXTRA_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-headers-extra.deb")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
  set(CPACK_DEBIAN_RUNTIME_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONTROL_EXTRA
    ${PROJECT_SOURCE_DIR}/cpack/debian/conffiles
    )

  if(FLB_RUN_LDCONFIG)
    set(LDCONFIG_DIR ${FLB_INSTALL_LIBDIR})
    file(WRITE ${PROJECT_BINARY_DIR}/scripts/postinst "
mkdir -p /etc/ld.so.conf.d
echo \"${LDCONFIG_DIR}\" > /etc/ld.so.conf.d/libfluent-bit.conf
ldconfig
    ")
    file(WRITE ${PROJECT_BINARY_DIR}/scripts/prerm "
rm -f -- /etc/ld.so.conf.d/libfluent-bit.conf
ldconfig
    ")
    set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONTROL_EXTRA "${PROJECT_BINARY_DIR}/scripts/postinst;${PROJECT_BINARY_DIR}/scripts/prerm")
  endif(FLB_RUN_LDCONFIG)

endif()

# RPM Generation information
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE})
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/cpack/description")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Fast data collector for Linux")
set(CPACK_RPM_SPEC_MORE_DEFINE "%define ignore \#")
set(CPACK_RPM_RUNTIME_USER_FILELIST
  "%config(noreplace) /etc/${FLB_OUT_NAME}/${FLB_OUT_NAME}.conf"
  "%config(noreplace) /etc/${FLB_OUT_NAME}/parsers.conf"
  "%config(noreplace) /etc/${FLB_OUT_NAME}/plugins.conf"
  "%ignore /lib"
  "%ignore /lib/systemd"
  "%ignore /lib/systemd/system"
  "%ignore /lib64"
  "%ignore /lib64/pkgconfig"
  "%ignore /usr/local"
  "%ignore /usr/local/bin"
  "%ignore /opt"
  "%ignore /etc")

set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
set(CPACK_RPM_HEADERS_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}-headers.rpm")
set(CPACK_RPM_HEADERS_EXTRA_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}-headers-extra.rpm")
set(CPACK_RPM_RUNTIME_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}.rpm")

# CPack: DEB
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# CPack: Windows System
if(CPACK_GENERATOR MATCHES "NSIS")
  set(CPACK_MONOLITHIC_INSTALL 1)
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "fluent-bit")
endif()

# CPack: Windows System w/ WiX
if(CPACK_GENERATOR MATCHES "WIX")
  set(CPACK_WIX_UPGRADE_GUID cb6825fd-37e6-4596-a55d-6d490d4fe178)
  configure_file(LICENSE "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt")
  configure_file(${CMAKE_SOURCE_DIR}/cpack/wix/WIX.template.in.cmakein
    ${CMAKE_CURRENT_BINARY_DIR}/WIX.template.in)
  # Specify LICENSE file that has .txt extension
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt")
  set(CPACK_WIX_TEMPLATE ${CMAKE_CURRENT_BINARY_DIR}/WIX.template.in)
  set(CPACK_WIX_LIGHT_EXTENSIONS "WixUtilExtension")
endif()

if(FLB_SYSTEM_MACOS)
  # Determine the platform suffix
  execute_process(
    COMMAND uname -m
    RESULT_VARIABLE UNAME_M_RESULT
    OUTPUT_VARIABLE UNAME_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "arm64")
    set(FLUENT_BIT_PKG ${CMAKE_CURRENT_BINARY_DIR}/fluent-bit-${FLB_VERSION_STR}-apple)
  elseif(UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "x86_64")
    set(FLUENT_BIT_PKG ${CMAKE_CURRENT_BINARY_DIR}/fluent-bit-${FLB_VERSION_STR}-intel)
  else()
    set(FLUENT_BIT_PKG ${CMAKE_CURRENT_BINARY_DIR}/fluent-bit-${FLB_VERSION_STR}-${UNAME_ARCH})
  endif()

  if (CPACK_GENERATOR MATCHES "productbuild")
    set(CPACK_SET_DESTDIR "ON")
    configure_file(cpack/macos/welcome.txt.cmakein ${CMAKE_CURRENT_BINARY_DIR}/welcome.txt)
    configure_file(cpack/macos/fluent-bit.plist.cmakein ${CMAKE_CURRENT_BINARY_DIR}/${FLB_OUT_NAME}.plist)
    configure_file(LICENSE ${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt)
    find_program(CONVERTER textutil)
    if (NOT CONVERTER)
      message(FATAL_ERROR "textutil not found.")
    endif()
    if (CONVERTER)
      execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_SOURCE_DIR}/README.md" -output "${CMAKE_BINARY_DIR}/README.html")
    endif()
    set(CPACK_PACKAGE_FILE_NAME "${FLUENT_BIT_PKG}")
    set(CPACK_RESOURCE_FILE_WELCOME ${CMAKE_CURRENT_BINARY_DIR}/welcome.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_BINARY_DIR}/LICENSE.txt)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_BINARY_DIR}/README.html)
    set(CPACK_PRODUCTBUILD_IDENTIFIER "io.fluentbit.${FLB_OUT_NAME}")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${FLB_OUT_NAME}.plist
      COMPONENT binary
      DESTINATION /Library/LaunchDaemons)
  endif()
endif()

include(CPack)
