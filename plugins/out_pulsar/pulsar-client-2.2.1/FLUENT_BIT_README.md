The other contents of this directory and the two subdirectories
necessary to build the pulsar-cpp-client originate from:

  https://github.com/apache/pulsar/tree/v2.2.1

The entire client was sufficiently large that it seemed excessive
to include it here.

There is one modification, to `pulsar-client-cpp/lib/CMakeLists.txt`
that was necessary to build pulsar via `add_subdirectory`. The patch
below will be submitted as a pull request to Apache at a later date.

```diff
diff --git a/pulsar-client-cpp/lib/CMakeLists.txt b/pulsar-client-cpp/lib/CMakeLists.txt
index 2116ed65a..3fecb009a 100644
--- a/pulsar-client-cpp/lib/CMakeLists.txt
+++ b/pulsar-client-cpp/lib/CMakeLists.txt
@@ -25,14 +25,14 @@ set (CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -D_PULSAR_VERSION_=\\\"${PV}\\\"")
 # Protobuf generation is only supported natively starting from CMake 3.8
 # Using custom command for now
 ADD_CUSTOM_COMMAND(
-         OUTPUT PulsarApi.pb.h PulsarApi.pb.cc
-         COMMAND protoc -I ../../pulsar-common/src/main/proto ../../pulsar-common/src/main/proto/PulsarApi.proto --cpp_out=${CMAKE_SOURCE_DIR}/lib
+         OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../lib/PulsarApi.pb.h ${CMAKE_CURRENT_SOURCE_DIR}/../lib/PulsarApi.pb.cc
+         COMMAND protoc -I ../../pulsar-common/src/main/proto ../../pulsar-common/src/main/proto/PulsarApi.proto --cpp_out=../lib
          DEPENDS
          ../../pulsar-common/src/main/proto/PulsarApi.proto
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

-add_library(pulsarStatic STATIC ${PULSAR_SOURCES} PulsarApi.pb.h PulsarApi.pb.cc)
-add_library(pulsarShared SHARED ${PULSAR_SOURCES} PulsarApi.pb.h PulsarApi.pb.cc)
+add_library(pulsarStatic STATIC ${PULSAR_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/../lib/PulsarApi.pb.h ${CMAKE_CURRENT_SOURCE_DIR}/../lib/PulsarApi.pb.cc)
+add_library(pulsarShared SHARED ${PULSAR_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/../lib/PulsarApi.pb.h ${CMAKE_CURRENT_SOURCE_DIR}/../lib/PulsarApi.pb.cc)

 set(LIBRARY_VERSION $ENV{PULSAR_LIBRARY_VERSION})
 if (NOT LIBRARY_VERSION)
@@ -48,4 +48,4 @@ target_link_libraries(pulsarShared ${COMMON_LIBS})
 install(TARGETS pulsarStatic DESTINATION lib)
 install(TARGETS pulsarShared DESTINATION lib)

-install(DIRECTORY "../include/pulsar" DESTINATION include)
\ No newline at end of file
+install(DIRECTORY "../include/pulsar" DESTINATION include)

```
