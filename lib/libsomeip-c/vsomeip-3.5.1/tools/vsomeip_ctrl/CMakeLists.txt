# Copyright (C) 2016-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# vsomeip_ctrl
add_executable(vsomeip_ctrl EXCLUDE_FROM_ALL vsomeip_ctrl.cpp)
target_link_libraries(vsomeip_ctrl
    vsomeip3
    ${Boost_LIBRARIES}
    ${DL_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
)

###################################################################################################

