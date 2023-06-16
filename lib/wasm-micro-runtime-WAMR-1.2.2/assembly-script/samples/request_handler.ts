/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

 // The entry file of your WebAssembly module.
import * as console from "../wamr_app_lib/console"
import * as timer from "../wamr_app_lib/timer"
import * as request from "../wamr_app_lib/request"

export function on_init() : void {
    request.register_resource_handler("/test", (req) => {
        console.log("### Req: /test  " + String.UTF8.decode(req.payload));

        console.log("    request payload:");
        console.log("    " + String.UTF8.decode(req.payload) + "\n");

        var resp = request.make_response_for_request(req);
        resp.set_payload(String.UTF8.encode("Ok"), 2);
        request.api_response_send(resp);
    });
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