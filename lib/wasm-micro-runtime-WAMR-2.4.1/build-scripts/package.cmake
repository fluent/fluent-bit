# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set(_WAMR_BUILD_SCRIPTS_DIR "${CMAKE_CURRENT_LIST_DIR}")

function(install_iwasm_package)
    install (EXPORT iwasmTargets
        FILE iwasmTargets.cmake
        NAMESPACE iwasm::
        DESTINATION lib/cmake/iwasm
    )

    include (CMakePackageConfigHelpers)
    configure_package_config_file (${_WAMR_BUILD_SCRIPTS_DIR}/iwasmConfig.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/iwasmConfig.cmake"
        INSTALL_DESTINATION lib/cmake/iwasm
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/iwasmConfigVersion.cmake"
        VERSION ${WAMR_VERSION_MAJOR}.${WAMR_VERSION_MINOR}.${WAMR_VERSION_PATCH}
        COMPATIBILITY SameMajorVersion
    )

    install (FILES
        "${CMAKE_CURRENT_BINARY_DIR}/iwasmConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/iwasmConfigVersion.cmake"
        DESTINATION lib/cmake/iwasm
    )
endfunction()
