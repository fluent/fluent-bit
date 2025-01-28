# Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project (vsomeip_utilities)

# ----------------------------------------------------------------------------
# Include all source files (cpp/hpp)
# ----------------------------------------------------------------------------
file (GLOB SRC src/*.cpp)
file (GLOB INC include/common/*.hpp, include/common/vsomeip_app_utilities/*.hpp)

# ----------------------------------------------------------------------------
# Declare the library
# ----------------------------------------------------------------------------
add_library (
    ${PROJECT_NAME} SHARED
    ${SRC}
    ${INC}
)

TARGET_LINK_LIBRARIES (
    ${PROJECT_NAME}
    PUBLIC
        ${VSOMEIP_NAME}
        ${Boost_LIBRARIES}
        ${DL_LIBRARY}
        ${TEST_LINK_LIBRARIES}
)

# ----------------------------------------------------------------------------
# Specify here the include directories exported
# by this library
# ----------------------------------------------------------------------------
target_include_directories (
    ${PROJECT_NAME}
    PUBLIC include
    PRIVATE src
)

if (MSVC)
	set_target_properties(${PROJECT_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()
