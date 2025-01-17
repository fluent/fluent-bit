
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

include(CMakeFindDependencyMacro)

if(ON)
  find_dependency(ZLIB)
endif()

if(Off)
  find_dependency(CURL)
endif()

if(ON)
  find_library(ZSTD zstd)
  if(NOT ZSTD)
    message(ERROR "ZSTD library not found!")
  else()
    message(STATUS "Found ZSTD: " ${ZSTD})
  endif()
endif()

if(ON)
  if()
    # TODO: custom SSL library should be installed
  else()
    find_dependency(OpenSSL)
  endif()
endif()

if(OFF)
  find_dependency(LZ4)
endif()

find_dependency(Threads)

include("${CMAKE_CURRENT_LIST_DIR}/RdKafkaTargets.cmake")
check_required_components("RdKafka")
