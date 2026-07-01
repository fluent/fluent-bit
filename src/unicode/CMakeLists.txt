include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  )

set(conv_src
  flb_conv.c
  flb_wchar.c
  flb_utf8_and_sjis.c     # cp932
  flb_utf8_and_gbk.c      # cp936
  flb_utf8_and_gb18030.c  # cp54936
  flb_utf8_and_uhc.c      # cp949
  flb_utf8_and_big5.c     # cp950
  flb_utf8_and_win.c      # cp1250, cp1251, cp1252, cp1253, cp1254, cp1256, cp866, cp874
  )

add_library(flb-conv STATIC ${conv_src})
if(FLB_JEMALLOC)
  target_link_libraries(flb-conv ${JEMALLOC_LIBRARIES})
endif()