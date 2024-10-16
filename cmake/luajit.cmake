# luajit cmake
option(LUAJIT_DIR "Path of LuaJIT 2.1 source dir" ON)
option(LUAJIT_SETUP_INCLUDE_DIR "Setup include dir if parent is present" OFF)
set(LUAJIT_DIR ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_LUAJIT})
include_directories(
  ${LUAJIT_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}/lib/luajit-cmake
)
add_subdirectory("lib/luajit-cmake")
set(LUAJIT_LIBRARIES "libluajit")
