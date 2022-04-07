set(src
  filter_avro.c)

if(MSVC)
  FLB_PLUGIN(filter_avro "${src}" "")
else()
  FLB_PLUGIN(filter_avro "${src}" "m")
endif()
