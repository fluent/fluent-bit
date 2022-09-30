/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

// The entry file of your WebAssembly module.
import * as console from '../wamr_app_lib/console'
import * as timer from '../wamr_app_lib/timer'

/* clousure is not implemented yet, we need to declare global variables
    so that they can be accessed inside a callback function */
var cnt = 0;
var my_timer: timer.user_timer;

export function on_init(): void {
    /* The callback function will be called every 2 second,
        and will stop after 10 calls */
    my_timer = timer.setInterval(() => {
        cnt ++;
        console.log((cnt * 2).toString() + " seconds passed");

        if (cnt >= 10) {
            timer.timer_cancel(my_timer);
            console.log("Stop Timer");
        }
    }, 2000);
}

export function on_destroy(): void {

}

/* Function below are requred by wamr runtime, don't remove or modify them */
export function _on_timer_callback(on_timer_id: i32): void {
    timer.on_timer_callback(on_timer_id);
}