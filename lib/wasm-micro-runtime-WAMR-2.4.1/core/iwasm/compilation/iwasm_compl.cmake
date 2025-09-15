set (IWASM_COMPL_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${IWASM_COMPL_DIR})
enable_language(CXX)

if (WAMR_BUILD_DEBUG_AOT EQUAL 1)
    file (GLOB_RECURSE source_all
                    ${IWASM_COMPL_DIR}/*.c
                    ${IWASM_COMPL_DIR}/*.cpp)
else()
    file (GLOB source_all
                    ${IWASM_COMPL_DIR}/simd/*.c
                    ${IWASM_COMPL_DIR}/simd/*.cpp
                    ${IWASM_COMPL_DIR}/*.c
                    ${IWASM_COMPL_DIR}/*.cpp)
endif()

set (IWASM_COMPL_SOURCE ${source_all})

# Disable rtti to works with LLVM

if (MSVC)
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GR-")
else()
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

