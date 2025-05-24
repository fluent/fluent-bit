set(src
  s3.c
  s3_store.c
  s3_multipart.c
  s3_parquet.c)

set(libs "")

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(libs
    ${libs}
    Shell32.lib
    Shlwapi.lib)
endif()

FLB_PLUGIN(out_s3 "${src}" "")
target_link_libraries(flb-plugin-out_s3 ${libs})
