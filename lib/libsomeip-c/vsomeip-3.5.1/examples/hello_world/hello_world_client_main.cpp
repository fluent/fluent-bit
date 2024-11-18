// Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
#include <csignal>
#endif
#include <vsomeip/vsomeip.hpp>
#include "hello_world_client.hpp"

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
hello_world_client *hw_cl_ptr(nullptr);
    void handle_signal(int _signal) {
        if (hw_cl_ptr != nullptr &&
                (_signal == SIGINT || _signal == SIGTERM))
            hw_cl_ptr->stop();
    }
#endif

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    hello_world_client hw_cl;
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    hw_cl_ptr = &hw_cl;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#endif
    if (hw_cl.init()) {
        hw_cl.start();
        return 0;
    } else {
        return 1;
    }
}
