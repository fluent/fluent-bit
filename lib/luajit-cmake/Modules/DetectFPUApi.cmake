
##===- DetectArchitecture.cmake -------------------------------------------===##
#
# Performs a try_compile to determine the architecture of the target.
#
##===----------------------------------------------------------------------===##

get_filename_component(__check_fpu_mode_dir "${CMAKE_CURRENT_LIST_FILE}" PATH)

macro(detect_fpu_mode variable)
  try_compile(HAVE_${variable}
    ${CMAKE_BINARY_DIR}
    ${__check_fpu_mode_dir}/DetectFpuAbi.c
    OUTPUT_VARIABLE OUTPUT
    COPY_FILE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/DetectFpuAbi.bin)

  if(HAVE_${variable})
    file(STRINGS ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/DetectFpuAbi.bin
    DETECT_FPU_STRING LIMIT_COUNT 1 REGEX "FPU IS")
    if(DETECT_FPU_STRING)
      string(REGEX MATCH "[^ ]*$" DETECT_FPU_MATCH ${DETECT_FPU_STRING})
      if(DETECT_FPU_MATCH)
        message(STATUS "Check target fpu: ${DETECT_FPU_STRING}")
        set(${variable} ${DETECT_FPU_MATCH})
      else()
        message(SEND_ERROR "Could not detect target fpu mode!")
      endif()
    else()
      message(SEND_ERROR "Could not detect fpu mode!")
    endif()
  else()
    message(STATUS "Determine the fpu mode - failed")
    file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
      "Determining the fpu mode failed with the following output:\n${OUTPUT}")
    set(${variable})
  endif()

endmacro(detect_fpu_mode)

macro(detect_fpu_abi variable)
  try_compile(HAVE_${variable}
    ${CMAKE_BINARY_DIR}
    ${__check_fpu_mode_dir}/DetectFpuAbi.c
    OUTPUT_VARIABLE OUTPUT
    COPY_FILE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/DetectFpuAbi.bin)

  if(HAVE_${variable})
    file(STRINGS ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/DetectFpuAbi.bin
    DETECT_FPU_ABI_STRING LIMIT_COUNT 1 REGEX "FPU ABI IS")
    if(DETECT_FPU_ABI_STRING)
      string(REGEX MATCH "[^ ]*$" DETECT_FPU_ABI_MATCH ${DETECT_FPU_ABI_STRING})
      if(DETECT_FPU_ABI_MATCH)
        message(STATUS "Check target fpu abi: ${DETECT_FPU_ABI_STRING}")
        set(${variable} ${DETECT_FPU_ABI_MATCH})
      else()
        message(SEND_ERROR "Could not detect target fpu abi!")
      endif()
    else()
      message(SEND_ERROR "Could not detect fpu abi!")
    endif()
  else()
    message(STATUS "Determine the fpu abi - failed")
    file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
      "Determining the fpu abi failed with the following output:\n${OUTPUT}")
    set(${variable})
  endif()

endmacro(detect_fpu_abi)
