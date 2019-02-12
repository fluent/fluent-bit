add_subdirectory(jsoncpp-1.7.7 EXCLUDE_FROM_ALL)

FLB_OPTION(CURL_STATICLIB On)
FLB_OPTION(BUILD_CURL_EXE Off)

add_subdirectory(curl-7.61.0 EXCLUDE_FROM_ALL)

# libpulsar build options
FLB_OPTION(BUILD_TESTS Off)
FLB_OPTION(BUILD_PYTHON_WRAPPER Off)
FLB_OPTION(LINK_STATIC On)
FLB_OPTION(USE_LOG4CXX Off)
FLB_OPTION(JSON_INCLUDE_PATH jsoncpp-1.7.7/include/)
FLB_OPTION(LIB_JSON jsoncpp_lib_static)
FLB_OPTION(CURL_LIBRARY_PATH libcurl)

# pulsar-client-cpp/lib/CMakeLists.txt attempts to set this itself
# by extracting it from a pom.xml file. That fails on our Docker
# builder without installing additional dependencies; this avoids
# that issue.
set( ENV{PULSAR_LIBRARY_VERSION} 2.2.1 )

# The pulsar-client-cpp project is not designed to be used via
# add_subdirectory, so we have to add some additional include
# directories before it is added.
include_directories(pulsar-client-2.2.1/pulsar-client-cpp/include/)
include_directories(pulsar-client-2.2.1/pulsar-client-cpp/)
include_directories(${JSON_INCLUDE_PATH})
include_directories(curl-7.61.0/include/)

add_subdirectory(pulsar-client-2.2.1/pulsar-client-cpp EXCLUDE_FROM_ALL)

# Fluent Bit Pulsar Output plugin
set(src
  pulsar.c
  pulsar_client.c
  pulsar_config.c
  pulsar_context.c)

FLB_PLUGIN(out_pulsar "${src}" "pulsarStatic")
