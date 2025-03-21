set(static_plugins "" CACHE INTERNAL "static_plugins")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# CHECK_STATIC_PLUGIN: Check if a plugin will be linked statically
macro(CHECK_STATIC_PLUGIN name)
  string(REPLACE "," ";" plugins ${MK_STATIC_PLUGINS})
  list(FIND plugins ${name} found)
  if(NOT found EQUAL -1)
    set(IS_STATIC TRUE)
  else()
    set(IS_STATIC FALSE)
  endif()
endmacro()

# MONKEY_PLUGIN: Used by plugins to register and create the targets
macro(MONKEY_PLUGIN name src)
  CHECK_STATIC_PLUGIN(${name})
  if(IS_STATIC)
    add_library(monkey-${name}-static STATIC ${src})
    set_target_properties(monkey-${name}-static PROPERTIES OUTPUT_NAME monkey-${name})
    set_target_properties(monkey-${name}-static PROPERTIES PREFIX "")
  else()
    if(APPLE)
      add_library(monkey-${name}-shared MODULE ${src})
    else()
      add_library(monkey-${name}-shared SHARED ${src})
    endif()
    set_target_properties(monkey-${name}-shared PROPERTIES OUTPUT_NAME monkey-${name})
    set_target_properties(monkey-${name}-shared PROPERTIES PREFIX "")

    if(NOT MK_LOCAL)
      if(CMAKE_INSTALL_LIBDIR)
        install(TARGETS monkey-${name}-shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
      else()
        install(TARGETS monkey-${name}-shared LIBRARY DESTINATION lib)
      endif()
    endif()
  endif()
endmacro()

# MK_BUILD_PLUGIN: This macro determinate if the plugin is enabled through the
# option MK_PLUGIN_NAME defined on the root CMakeLists.txt
macro(MK_BUILD_PLUGIN name)
  set(mode "")
  string(TOUPPER ${name} NAME)

  # Check if the plugin is enabled
  set(option MK_PLUGIN_${NAME})
  if(${option})
    add_subdirectory(${name})

    # Is this a static plugin ?
    CHECK_STATIC_PLUGIN(${name})
    if(IS_STATIC)
      # Let Monkey and CMake aware about this is a static plugin. A static plugin
      # requires a different handling: link the object and register the plugin
      # struct reference on mk_static_plugins.h
      set(static_plugins "${static_plugins}monkey-${name}-static;")
      set(STATIC_PLUGINS_INIT "${STATIC_PLUGINS_INIT}\n    mk_static_plugin_attach(plugins, &mk_plugin_${name});\n")
      set(STATIC_PLUGINS_DECL "${STATIC_PLUGINS_DECL}extern struct mk_plugin mk_plugin_${name};\n")

      # append message to stdout
      set(mode "[== static ==]")
    else()
      if(MK_LOCAL)
        set(MK_LOAD_PLUGINS "${MK_LOAD_PLUGINS}    # Load ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/monkey-${name}.so\n")
      else()
        set(MK_LOAD_PLUGINS "${MK_LOAD_PLUGINS}    # Load ${CMAKE_INSTALL_FULL_LIBDIR}/monkey-${name}.so\n")
      endif()
    endif()
    message(STATUS "Plugin ${name} enabled ${mode}")
  endif()
endmacro()


macro(MONKEY_PLUGIN_LINK_LIB target lib)
  CHECK_STATIC_PLUGIN(${target})
  if(IS_STATIC)
    target_link_libraries(monkey-${target}-static ${lib})
  else()
    target_link_libraries(monkey-${target}-shared ${lib})
  endif()
endmacro()

# Try to configure/build all plugins
MK_BUILD_PLUGIN("auth")
MK_BUILD_PLUGIN("cgi")
MK_BUILD_PLUGIN("cheetah")
MK_BUILD_PLUGIN("dirlisting")
MK_BUILD_PLUGIN("fastcgi")
MK_BUILD_PLUGIN("liana")
MK_BUILD_PLUGIN("logger")
MK_BUILD_PLUGIN("mandril")
MK_BUILD_PLUGIN("tls")
MK_BUILD_PLUGIN("duda")

# Generate include/monkey/mk_static_plugins.h
configure_file(
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_static_plugins.h.in"
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_static_plugins.h"
  )

# Generate conf/plugins.load
if(NOT MK_WITHOUT_CONF)
  configure_file(
    "${PROJECT_SOURCE_DIR}/conf/plugins.load.in"
    "${PROJECT_BINARY_DIR}/conf/plugins.load"
    )
endif()

set(STATIC_PLUGINS_LIBS "${static_plugins}" PARENT_SCOPE)
