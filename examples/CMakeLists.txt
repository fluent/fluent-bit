add_subdirectory(hello_world)
if(FLB_OUT_LIB)
  add_subdirectory(out_lib)
endif()

if(NOT FLB_SYSTEM_WINDOWS)
  add_subdirectory(hello_world_cpp)
  add_subdirectory(td_cpp)
endif()
