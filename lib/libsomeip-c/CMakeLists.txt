project(someipc CXX)

include(FetchContent)
FetchContent_Declare(
    vsomeip3
    GIT_REPOSITORY https://github.com/COVESA/vsomeip
    GIT_TAG        0b83e24d16e1611958194e9b727136522f46556b # 3.5.1
)
FetchContent_MakeAvailable(vsomeip3)

find_package(vsomeip3 REQUIRED)

add_library(someip-c SHARED src/someip_wrapper.cc)
target_include_directories(someip-c PUBLIC include)
target_link_libraries(someip-c PRIVATE vsomeip3 vsomeip3-sd vsomeip3-cfg vsomeip3-e2e)
target_link_options(someip-c PUBLIC "-Wl,--disable-new-dtags")

add_subdirectory(example)