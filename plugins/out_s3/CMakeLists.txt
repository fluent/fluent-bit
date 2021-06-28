set(src
  s3.c
  s3_store.c
  s3_multipart.c)

FLB_PLUGIN(out_s3 "${src}" "")

if(FLB_ARROW)
  add_subdirectory(arrow EXCLUDE_FROM_ALL)
  target_link_libraries(flb-plugin-out_s3 out-s3-arrow)
endif()
