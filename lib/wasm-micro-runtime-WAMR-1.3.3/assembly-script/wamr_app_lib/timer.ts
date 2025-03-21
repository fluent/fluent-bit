/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

@external("env", "wasm_create_timer")
declare function wasm_create_timer(a: i32, b: bool, c: bool): i32;

@external("env", "wasm_timer_cancel")
declare function wasm_timer_cancel(a: i32): void;

@external("env", "wasm_timer_restart")
declare function wasm_timer_restart(a: i32, b: i32): void;

@external("env", "wasm_get_sys_tick_ms")
declare function wasm_get_sys_tick_ms(): i32;

export var timer_list = new Array<user_timer>();

export class user_timer {
    timer_id: i32 = 0;
    timeout: i32;
    period: bool = false;
    cb: () => void;

    constructor(cb: () => void, timeout: i32, period: bool) {
        this.cb = cb;
        this.timeout = timeout;
        this.period = period
        this.timer_id = timer_create(this.timeout, this.period, true);
    }
}

export function timer_create(a: i32, b: bool, c: bool): i32 {
    return wasm_create_timer(a, b, c);
}

export function setTimeout(cb: () => void, timeout: i32): user_timer {
    var timer = new user_timer(cb, timeout, false);
    timer_list.push(timer);

    return timer;
}

export function setInterval(cb: () => void, timeout: i32): user_timer {
    var timer = new user_timer(cb, timeout, true);
    timer_list.push(timer);

    return timer;
}

export function timer_cancel(timer: user_timer): void {
    wasm_timer_cancel(timer.timer_id);

    var i = 0;
    for (i = 0; i < timer_list.length; i++) {
        if (timer_list[i].timer_id == timer.timer_id)
            break;
    }

    timer_list.splice(i, 1);
}

export function timer_restart(timer: user_timer, interval: number): void {
    wasm_timer_restart(timer.timer_id, i32(interval));
}

export function now(): i32 {
    return wasm_get_sys_tick_ms();
}

// This export function need to be copied to the top application file
//
export function on_timer_callback(on_timer_id: i32): void {
    for (let i = 0; i < timer_list.length; i++) {
        if (timer_list[i].timer_id == on_timer_id) {
            timer_list[i].cb();
        }
    }
}