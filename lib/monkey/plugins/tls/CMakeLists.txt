if(NOT DEFINED MK_TLS_PLUGIN_SRC)
  message(FATAL_ERROR "TLS backend was not configured. Enable MK_PLUGIN_TLS and configure tls/CMakeLists.txt")
endif()

MONKEY_PLUGIN(tls "${MK_TLS_PLUGIN_SRC}")

foreach(lib ${MK_TLS_PLUGIN_LIBS})
  MONKEY_PLUGIN_LINK_LIB(tls ${lib})
endforeach()
add_subdirectory(conf)
