cmake_minimum_required(VERSION 3.20)
project(cfl_installed_consumer C)

find_package(Threads REQUIRED)
find_path(CFL_INCLUDE_DIR NAMES cfl/cfl.h REQUIRED)
find_library(CFL_LIBRARY NAMES cfl REQUIRED)
find_library(XXHASH_LIBRARY NAMES xxhash REQUIRED)

add_executable(cfl-installed-consumer main.c)
target_include_directories(cfl-installed-consumer PRIVATE ${CFL_INCLUDE_DIR})
target_link_libraries(cfl-installed-consumer
  PRIVATE
    ${CFL_LIBRARY}
    ${XXHASH_LIBRARY}
    Threads::Threads)
