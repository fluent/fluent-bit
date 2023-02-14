# luajit cmake
option(LUAJIT_DIR "Path of LuaJIT 2.1 source dir" ON)
set(LUAJIT_DIR ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_LUAJIT})
add_subdirectory("lib/luajit-cmake")
