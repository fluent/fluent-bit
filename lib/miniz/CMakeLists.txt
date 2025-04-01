cmake_minimum_required(VERSION 3.20)

# determine whether this is a standalone project or included by other projects
set (MINIZ_STANDALONE_PROJECT ON)
if(DEFINED PROJECT_NAME)
  set(MINIZ_STANDALONE_PROJECT OFF)
endif()

if(CMAKE_MINOR_VERSION LESS 12)
  project(miniz C)
  # see issue https://gitlab.kitware.com/cmake/cmake/merge_requests/1799
else()
  project(miniz C)
  set(CMAKE_C_STANDARD 90)
  set(CMAKE_VERBOSE_MAKEFILE ON)
  # set(CMAKE_C_VISIBILITY_PRESET hidden)
  # set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

  if (MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /Zi /permissive-")
  else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wformat=2 -Wall -Wno-overlength-strings -pedantic")
  endif ()
endif()

set(MINIZ_API_VERSION 3)
set(MINIZ_MINOR_VERSION 0)
set(MINIZ_PATCH_VERSION 0)
set(MINIZ_VERSION
    ${MINIZ_API_VERSION}.${MINIZ_MINOR_VERSION}.${MINIZ_PATCH_VERSION})

if(CMAKE_BUILD_TYPE STREQUAL "")
  # CMake defaults to leaving CMAKE_BUILD_TYPE empty. This screws up
  # differentiation between debug and release builds.
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
    "Choose the type of build, options are: None (CMAKE_CXX_FLAGS or \
CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif ()

option(BUILD_EXAMPLES "Build examples" ${MINIZ_STANDALONE_PROJECT})
option(BUILD_FUZZERS "Build fuzz targets" OFF)
option(AMALGAMATE_SOURCES "Amalgamate sources into miniz.h/c" OFF)
option(BUILD_HEADER_ONLY "Build a header-only version" OFF)
option(BUILD_SHARED_LIBS "Build shared library instead of static" OFF)
option(INSTALL_PROJECT "Install project" ${MINIZ_STANDALONE_PROJECT})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

if(INSTALL_PROJECT)
  include(GNUInstallDirs)
endif()

if(BUILD_HEADER_ONLY)
  set(AMALGAMATE_SOURCES ON CACHE BOOL "Build a header-only version" FORCE)
endif(BUILD_HEADER_ONLY)

if(AMALGAMATE_SOURCES)
  # Amalgamate
  file(COPY miniz.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/)
  file(READ miniz.h MINIZ_H)
  file(READ miniz_common.h MINIZ_COMMON_H)
  file(READ miniz_tdef.h MINIZ_TDEF_H)
  file(READ miniz_tinfl.h MINIZ_TINFL_H)
  file(READ miniz_zip.h MINIZ_ZIP_H)
  file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.h
     "${MINIZ_COMMON_H} ${MINIZ_TDEF_H} ${MINIZ_TINFL_H} ${MINIZ_ZIP_H}")

  file(COPY miniz.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/)
  file(READ miniz_tdef.c MINIZ_TDEF_C)
  file(READ miniz_tinfl.c MINIZ_TINFL_C)
  file(READ miniz_zip.c MINIZ_ZIP_C)
  file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.c
     "${MINIZ_TDEF_C} ${MINIZ_TINFL_C} ${MINIZ_ZIP_C}")

  file(READ ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.h AMAL_MINIZ_H)
  file(READ ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.c AMAL_MINIZ_C)
  foreach(REPLACE_STRING miniz;miniz_common;miniz_tdef;miniz_tinfl;miniz_zip;miniz_export)
    string(REPLACE "#include \"${REPLACE_STRING}.h\"" "" AMAL_MINIZ_H "${AMAL_MINIZ_H}")
    string(REPLACE "#include \"${REPLACE_STRING}.h\"" "" AMAL_MINIZ_C "${AMAL_MINIZ_C}")
  endforeach()
  string(CONCAT AMAL_MINIZ_H "#ifndef MINIZ_EXPORT\n#define MINIZ_EXPORT\n#endif\n" "${AMAL_MINIZ_H}")
  if(BUILD_HEADER_ONLY)
    string(CONCAT AMAL_MINIZ_H "${AMAL_MINIZ_H}" "\n#ifndef MINIZ_HEADER_FILE_ONLY\n"
             "${AMAL_MINIZ_C}" "\n#endif // MINIZ_HEADER_FILE_ONLY\n")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.h "${AMAL_MINIZ_H}")
    add_library(${PROJECT_NAME} INTERFACE)

    # Might not be a good idea to force this on the library user
    # as it could bloat the global namespace
    # https://github.com/libevent/libevent/issues/460
    # target_compile_definitions(${PROJECT_NAME}
    #     INTERFACE $<$<C_COMPILER_ID:GNU>:_GNU_SOURCE>)

    set_property(TARGET ${PROJECT_NAME} APPEND
      PROPERTY INTERFACE_INCLUDE_DIRECTORIES
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/amalgamation>
      $<INSTALL_INTERFACE:include>
    )
  else(BUILD_HEADER_ONLY)
    string(CONCAT AMAL_MINIZ_C "#include \"miniz.h\"\n" "${AMAL_MINIZ_C}")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.h "${AMAL_MINIZ_H}")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.c "${AMAL_MINIZ_C}")
    set(miniz_SOURCE ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.h
                     ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.c)
    add_library(${PROJECT_NAME} STATIC ${miniz_SOURCE})
    target_include_directories(${PROJECT_NAME} PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/amalgamation>
      $<INSTALL_INTERFACE:include>
    )
  endif(BUILD_HEADER_ONLY)

  set(INSTALL_HEADERS ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/miniz.h)

  file(GLOB_RECURSE ZIP_FILES RELATIVE "${CMAKE_CURRENT_BINARY_DIR}/amalgamation" "${CMAKE_CURRENT_BINARY_DIR}/amalgamation/*")
  file(GLOB_RECURSE ZIP_FILES2 RELATIVE "${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/examples/*")
  list(APPEND ZIP_FILES ${ZIP_FILES2})
  list(APPEND ZIP_FILES "ChangeLog.md")
  list(APPEND ZIP_FILES "readme.md")
  list(APPEND ZIP_FILES "LICENSE")
  set(ZIP_OUT_FN "${CMAKE_CURRENT_BINARY_DIR}/miniz-${MINIZ_VERSION}.zip")
  message(STATUS "Zip files: ${ZIP_FILES}")
  add_custom_command(
		COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/examples ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/examples
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/ChangeLog.md ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/ChangeLog.md
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/readme.md ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/readme.md
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_BINARY_DIR}/amalgamation/LICENSE
		COMMAND ${CMAKE_COMMAND} -E tar "cf" "${ZIP_OUT_FN}" --format=zip -- ${ZIP_FILES}
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/amalgamation"
        OUTPUT  "${ZIP_OUT_FN}"
        DEPENDS ${ZIP_FILES}
        COMMENT "Zipping to ${CMAKE_CURRENT_BINARY_DIR}/miniz.zip."
    )

	add_custom_target(
	  create_zip ALL
	  DEPENDS "${ZIP_OUT_FN}"
	)
else(AMALGAMATE_SOURCES)
  include(GenerateExportHeader)
  set(miniz_SOURCE miniz.c miniz_zip.c miniz_tinfl.c miniz_tdef.c)
  add_library(${PROJECT_NAME} ${miniz_SOURCE})
  generate_export_header(${PROJECT_NAME})

  if(NOT BUILD_SHARED_LIBS)
    string(TOUPPER ${PROJECT_NAME} PROJECT_UPPER)
    set_target_properties(${PROJECT_NAME}
        PROPERTIES INTERFACE_COMPILE_DEFINITIONS ${PROJECT_UPPER}_STATIC_DEFINE)
  else()
    set_property(TARGET ${PROJECT_NAME} PROPERTY C_VISIBILITY_PRESET hidden)
  endif()

  set_property(TARGET ${PROJECT_NAME} PROPERTY VERSION ${MINIZ_VERSION})
  set_property(TARGET ${PROJECT_NAME} PROPERTY SOVERSION ${MINIZ_API_VERSION})

  target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:include>
  )

  file(GLOB INSTALL_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
  list(APPEND
       INSTALL_HEADERS ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}_export.h)
endif(AMALGAMATE_SOURCES)

if(NOT BUILD_HEADER_ONLY)
  target_compile_definitions(${PROJECT_NAME}
    PRIVATE $<$<C_COMPILER_ID:GNU>:_GNU_SOURCE>)

  # pkg-config file
  configure_file(miniz.pc.in ${CMAKE_CURRENT_BINARY_DIR}/miniz.pc @ONLY)

  if(INSTALL_PROJECT)
    install(FILES
      ${CMAKE_CURRENT_BINARY_DIR}/miniz.pc
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
  endif()
endif()

set_property(TARGET ${PROJECT_NAME} PROPERTY
  INTERFACE_${PROJECT_NAME}_MAJOR_VERSION ${MINIZ_API_VERSION})
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY
  COMPATIBLE_INTERFACE_STRING ${PROJECT_NAME}_MAJOR_VERSION
)

if(INSTALL_PROJECT)
  install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}Targets
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    # users can use <miniz.h> or <miniz/miniz.h>
    INCLUDES DESTINATION include ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
  )

  include(CMakePackageConfigHelpers)
  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${MINIZ_VERSION}
    COMPATIBILITY AnyNewerVersion
  )

  export(EXPORT ${PROJECT_NAME}Targets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}Targets.cmake"
    NAMESPACE ${PROJECT_NAME}::
  )
  configure_file(Config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}Config.cmake"
    @ONLY
  )

  set(ConfigPackageLocation ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
  install(EXPORT ${PROJECT_NAME}Targets
    FILE
      ${PROJECT_NAME}Targets.cmake
    NAMESPACE
      ${PROJECT_NAME}::
    DESTINATION
      ${ConfigPackageLocation}
  )
  install(
    FILES
      "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}Config.cmake"
      "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION
      ${ConfigPackageLocation}
    COMPONENT
      Devel
  )
endif()

if(BUILD_EXAMPLES)
  set(EXAMPLE1_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/examples/example1.c")
  set(EXAMPLE2_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/examples/example2.c")
  set(EXAMPLE3_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/examples/example3.c")
  set(EXAMPLE4_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/examples/example4.c")
  set(EXAMPLE5_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/examples/example5.c")
  set(EXAMPLE6_SRC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/examples/example6.c")
  set(MINIZ_TESTER_SRC_LIST
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/miniz_tester.cpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/timer.cpp")

  add_executable(example1 ${EXAMPLE1_SRC_LIST})
  target_link_libraries(example1 miniz)
  add_executable(example2 ${EXAMPLE2_SRC_LIST})
  target_link_libraries(example2 miniz)
  add_executable(example3 ${EXAMPLE3_SRC_LIST})
  target_link_libraries(example3 miniz)
  add_executable(example4 ${EXAMPLE4_SRC_LIST})
  target_link_libraries(example4 miniz)
  add_executable(example5 ${EXAMPLE5_SRC_LIST})
  target_link_libraries(example5 miniz)
  add_executable(example6 ${EXAMPLE6_SRC_LIST})
  target_link_libraries(example6 miniz)
  if(${UNIX})
      target_link_libraries(example6 m)
  endif()

  # add_executable(miniz_tester ${MINIZ_TESTER_SRC_LIST})
  # target_link_libraries(miniz_tester miniz)
endif(BUILD_EXAMPLES)

if(BUILD_FUZZERS)
  set(FUZZ_MAIN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz_main.c")

  set(CHECKSUM_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/checksum_fuzzer.c")
  set(FLUSH_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/flush_fuzzer.c")
  set(UNCOMPRESS_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/uncompress_fuzzer.c")
  set(UNCOMPRESS2_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/uncompress2_fuzzer.c")
  set(COMPRESS_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/compress_fuzzer.c")
  set(SMALL_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/small_fuzzer.c")
  set(LARGE_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/large_fuzzer.c")
  set(ZIP_FUZZER_SRC_LIST "${FUZZ_MAIN_SRC}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/zip_fuzzer.c")

  add_executable(checksum_fuzzer ${CHECKSUM_FUZZER_SRC_LIST})
  target_link_libraries(checksum_fuzzer miniz)

  add_executable(flush_fuzzer ${FLUSH_FUZZER_SRC_LIST})
  target_link_libraries(flush_fuzzer miniz)

  add_executable(uncompress_fuzzer ${UNCOMPRESS_FUZZER_SRC_LIST})
  target_link_libraries(uncompress_fuzzer miniz)

  add_executable(uncompress2_fuzzer ${UNCOMPRESS2_FUZZER_SRC_LIST})
  target_link_libraries(uncompress2_fuzzer miniz)

  add_executable(compress_fuzzer ${COMPRESS_FUZZER_SRC_LIST})
  target_link_libraries(compress_fuzzer miniz)

  add_executable(small_fuzzer ${SMALL_FUZZER_SRC_LIST})
  target_link_libraries(small_fuzzer miniz)

  add_executable(large_fuzzer ${LARGE_FUZZER_SRC_LIST})
  target_link_libraries(large_fuzzer miniz)

  add_executable(zip_fuzzer ${ZIP_FUZZER_SRC_LIST})
  target_link_libraries(zip_fuzzer miniz)
endif()

set(INCLUDE_INSTALL_DIR "include")

if(INSTALL_PROJECT)
  install(FILES ${INSTALL_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
endif()

