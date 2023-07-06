/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

// The entry file of your WebAssembly module.
import * as console from "../wamr_app_lib/console"
import * as timer from "../wamr_app_lib/timer"
import * as request from "../wamr_app_lib/request"

export function on_init() : void {
    request.subscribe_event("alert/overheat", (req) => {
        console.log("### user over heat event handler called:");

        console.log("");
        console.log("    " + String.UTF8.decode(req.payload) + "\n");
    })
}

export function on_destroy() : void {

}


/* Function below are requred by wamr runtime, don't remove or modify them */
export function _on_timer_callback(on_timer_id: i32): void {
    timer.on_timer_callback(on_timer_id);
}

export function _on_request(buffer_offset: i32, size: i32): void {
    request.on_request(buffer_offset, size);
}

export function _on_response(buffer_offset : i32, size: i32): void {
    request.on_response(buffer_offset, size);
}