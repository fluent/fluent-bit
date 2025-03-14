project(someipc CXX)

find_package(vsomeip3 QUIET)

if(NOT(vsomeip3_FOUND))
  MESSAGE(STATUS "vsomeip not found disabling SOMEIP input plugin")
  set(FLB_IN_SOMEIP OFF PARENT_SCOPE)
else()
  MESSAGE(DEBUG "Found vsomeip package. Adding in someip-c library.")
  add_library(someip-c SHARED src/someip_wrapper.cc)
  target_include_directories(someip-c PUBLIC include)
  target_link_libraries(someip-c PRIVATE vsomeip3 vsomeip3-sd vsomeip3-cfg vsomeip3-e2e)
  target_link_options(someip-c PUBLIC "-Wl,--disable-new-dtags")

  add_subdirectory(example)
endif()
