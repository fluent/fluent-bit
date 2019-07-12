add_subdirectory(hello_world)

if(NOT FLB_SYSTEM_WINDOWS)
  add_subdirectory(hello_world_cpp)
  add_subdirectory(td_cpp)
  add_subdirectory(out_lib)
endif()
