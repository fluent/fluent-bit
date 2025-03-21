
##===- DetectArchitecture.cmake -------------------------------------------===##
#
# Performs a try_compile to determine the architecture of the target.
#
##===----------------------------------------------------------------------===##
get_filename_component(__check_architecture_size_dir "${CMAKE_CURRENT_LIST_FILE}" PATH)

macro(detect_architecture variable)
  try_compile(HAVE_${variable}
    ${CMAKE_BINARY_DIR}
    ${__check_architecture_size_dir}/DetectArchitecture.c
    OUTPUT_VARIABLE OUTPUT
    COPY_FILE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/DetectArchitecture.bin)

  if(HAVE_${variable})
    file(STRINGS ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/DetectArchitecture.bin
      DETECT_ARCH_STRING LIMIT_COUNT 1 REGEX "ARCHITECTURE IS")
    if(DETECT_ARCH_STRING)
      string(REGEX MATCH "[^ ]*$" DETECT_ARCH_MATCH ${DETECT_ARCH_STRING})
      if(DETECT_ARCH_MATCH)
        message(STATUS "Check target system architecture: ${DETECT_ARCH_MATCH}")
        set(${variable} ${DETECT_ARCH_MATCH})
      else()
        message(SEND_ERROR "Could not detect target system architecture!")
      endif()
    else()
      message(SEND_ERROR "Could not detect target system architecture!")
    endif()
  else()
    message(STATUS "Determine the system architecture - failed")
    file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
      "Determining the system architecture failed with the following output:\n${OUTPUT}")
    set(${variable})
  endif()

endmacro(detect_architecture)
