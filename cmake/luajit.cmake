# luajit cmake
option(LUAJIT_DIR "Path of LuaJIT 2.1 source dir" ON)
option(LUAJIT_SETUP_INCLUDE_DIR "Setup include dir if parent is present" OFF)
set(LUAJIT_DIR ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_LUAJIT})
add_subdirectory("lib/luajit-cmake")
