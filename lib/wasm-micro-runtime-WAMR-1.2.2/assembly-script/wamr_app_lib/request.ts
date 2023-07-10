/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as console from './console'
import * as timer from './timer'

@external("env", "wasm_response_send")
declare function wasm_response_send(buffer: ArrayBuffer, size: i32): bool;

@external("env", "wasm_register_resource")
declare function wasm_register_resource(url: ArrayBuffer): void;

@external("env", "wasm_post_request")
declare function wasm_post_request(buffer: ArrayBuffer, size: i32): void;

@external("env", "wasm_sub_event")
declare function wasm_sub_event(url: ArrayBuffer): void;

var COAP_GET = 1;
var COAP_POST = 2;
var COAP_PUT = 3;
var COAP_DELETE = 4;
var COAP_EVENT = COAP_DELETE + 2;

/* CoAP response codes */
export enum CoAP_Status {
    NO_ERROR = 0,

    CREATED_2_01 = 65, /* CREATED */
    DELETED_2_02 = 66, /* DELETED */
    VALID_2_03 = 67, /* NOT_MODIFIED */
    CHANGED_2_04 = 68, /* CHANGED */
    CONTENT_2_05 = 69, /* OK */
    CONTINUE_2_31 = 95, /* CONTINUE */

    BAD_REQUEST_4_00 = 128, /* BAD_REQUEST */
    UNAUTHORIZED_4_01 = 129, /* UNAUTHORIZED */
    BAD_OPTION_4_02 = 130, /* BAD_OPTION */
    FORBIDDEN_4_03 = 131, /* FORBIDDEN */
    NOT_FOUND_4_04 = 132, /* NOT_FOUND */
    METHOD_NOT_ALLOWED_4_05 = 133, /* METHOD_NOT_ALLOWED */
    NOT_ACCEPTABLE_4_06 = 134, /* NOT_ACCEPTABLE */
    PRECONDITION_FAILED_4_12 = 140, /* BAD_REQUEST */
    REQUEST_ENTITY_TOO_LARGE_4_13 = 141, /* REQUEST_ENTITY_TOO_LARGE */
    UNSUPPORTED_MEDIA_TYPE_4_15 = 143, /* UNSUPPORTED_MEDIA_TYPE */

    INTERNAL_SERVER_ERROR_5_00 = 160, /* INTERNAL_SERVER_ERROR */
    NOT_IMPLEMENTED_5_01 = 161, /* NOT_IMPLEMENTED */
    BAD_GATEWAY_5_02 = 162, /* BAD_GATEWAY */
    SERVICE_UNAVAILABLE_5_03 = 163, /* SERVICE_UNAVAILABLE */
    GATEWAY_TIMEOUT_5_04 = 164, /* GATEWAY_TIMEOUT */
    PROXYING_NOT_SUPPORTED_5_05 = 165, /* PROXYING_NOT_SUPPORTED */

    /* Erbium errors */
    MEMORY_ALLOCATION_ERROR = 192, PACKET_SERIALIZATION_ERROR,

    /* Erbium hooks */
    MANUAL_RESPONSE, PING_RESPONSE
};

var g_mid: i32 = 0;
class wamr_request {
    mid: i32 = 0;
    url: string = "";
    action: i32 = 0;
    fmt: i32 = 0;
    payload: ArrayBuffer;
    payload_len: i32 = 0;

    sender: i32 = 0;

    constructor(mid: i32, url: string, action: i32, fmt: i32,
        payload: ArrayBuffer, payload_len: number) {
        this.mid = mid;
        this.url = url;
        this.action = action;
        this.fmt = fmt;
        this.payload = payload;
        this.payload_len = i32(payload_len);
    }
}

class wamr_response {
    mid: i32 = 0;
    status: i32 = 0;
    fmt: i32 = 0;
    payload: ArrayBuffer | null;
    payload_len: i32 = 0;

    receiver: i32 = 0;

    constructor(mid: i32, status: i32, fmt: i32,
        payload: ArrayBuffer | null, payload_len: i32) {
        this.mid = mid;
        this.status = status;
        this.fmt = fmt;
        this.payload = payload;
        this.payload_len = payload_len;
    }

    set_status(status: number): void {
        this.status = i32(status);
    }

    set_payload(payload: ArrayBuffer, payload_len: number): void {
        this.payload = payload;
        this.payload_len = i32(payload_len);
    }
}

class wamr_resource {
    url: string;
    type: number;
    cb: request_handler_f;

    constructor(url: string, type: number, cb: request_handler_f) {
        this.url = url;
        this.type = type;
        this.cb = cb;
    }
}

function is_expire(trans: wamr_transaction, index: i32, array: Array<wamr_transaction>): bool {
    var now = timer.now();

    var elapsed_ms = (now < trans.time) ?
        (now + (0xFFFFFFFF - trans.time) + 1) : (now - trans.time);

    return elapsed_ms >= TRANSACTION_TIMEOUT_MS;
}

function not_expire(trans: wamr_transaction, index: i32, array: Array<wamr_transaction>): bool {
    var now = timer.now();

    var elapsed_ms = (now < trans.time) ?
        (now + (0xFFFFFFFF - trans.time) + 1) : (now - trans.time);

    return elapsed_ms < TRANSACTION_TIMEOUT_MS;
}

function transaction_timeout_handler(): void {
    var now = timer.now();

    var expired = transaction_list.filter(is_expire);
    transaction_list = transaction_list.filter(not_expire);

    expired.forEach(item => {
        item.cb(null);
        transaction_remove(item);
    })

    if (transaction_list.length > 0) {
        var elpased_ms: number, ms_to_expiry: number;
        now = timer.now();
        if (now < transaction_list[0].time) {
            elpased_ms = now + (0xFFFFFFFF - transaction_list[0].time) + 1;
        } else {
            elpased_ms = now - transaction_list[0].time;
        }
        ms_to_expiry = TRANSACTION_TIMEOUT_MS - elpased_ms;
        timer.timer_restart(g_trans_timer, ms_to_expiry);
    } else {
        timer.timer_cancel(g_trans_timer);
    }
}

function transaction_find(mid: number): wamr_transaction | null {
    for (let i = 0; i < transaction_list.length; i++) {
        if (transaction_list[i].mid == mid)
            return transaction_list[i];
    }
    return null;
}

function transaction_add(trans: wamr_transaction): void {
    transaction_list.push(trans);

    if (transaction_list.length == 1) {
        g_trans_timer = timer.setTimeout(
            transaction_timeout_handler,
            TRANSACTION_TIMEOUT_MS
        );
    }
}

function transaction_remove(trans: wamr_transaction): void {
    var index = transaction_list.indexOf(trans);
    transaction_list.splice(index, 1);
}

var transaction_list = new Array<wamr_transaction>();
class wamr_transaction {
    mid: number;
    time: number;
    cb: (resp: wamr_response | null) => void;

    constructor(mid: number, time: number, cb: (resp: wamr_response) => void) {
        this.mid = mid;
        this.time = time;
        this.cb = cb;
    }
}

var REQUEST_PACKET_FIX_PART_LEN = 18;
var RESPONSE_PACKET_FIX_PART_LEN = 16;
var TRANSACTION_TIMEOUT_MS = 5000;
var g_trans_timer: timer.user_timer;

var Reg_Event = 0;
var Reg_Request = 1;

function pack_request(req: wamr_request): DataView {
    var url_len = req.url.length + 1;
    var len = REQUEST_PACKET_FIX_PART_LEN + url_len + req.payload_len
    var buf = new ArrayBuffer(len);

    var dataview = new DataView(buf, 0, len);

    dataview.setUint8(0, 1);
    dataview.setUint8(1, u8(req.action));
    dataview.setUint16(2, u16(req.fmt));
    dataview.setUint32(4, req.mid);
    dataview.setUint32(8, req.sender);
    dataview.setUint16(12, u16(url_len))
    dataview.setUint32(14, req.payload_len);

    var i = 0;
    for (i = 0; i < url_len - 1; i++) {
        dataview.setUint8(i + 18, u8(req.url.codePointAt(i)));
    }
    dataview.setUint8(i + 18, 0);

    var payload_view = new DataView(req.payload);
    for (i = 0; i < req.payload_len; i++) {
        dataview.setUint8(i + 18 + url_len, u8(payload_view.getUint8(i)));
    }

    return dataview;
}

function unpack_request(packet: ArrayBuffer, size: i32): wamr_request {
    var dataview = new DataView(packet, 0, size);

    if (dataview.getUint8(0) != 1)
        throw new Error("packet version mismatch");

    if (size < REQUEST_PACKET_FIX_PART_LEN)
        throw new Error("packet size error");

    var url_len = dataview.getUint16(12);
    var payload_len = dataview.getUint32(14);

    if (size != (REQUEST_PACKET_FIX_PART_LEN + url_len + payload_len))
        throw new Error("packet size error");

    var action = dataview.getUint8(1);
    var fmt = dataview.getUint16(2);
    var mid = dataview.getUint32(4);
    var sender = dataview.getUint32(8);

    var url = packet.slice(REQUEST_PACKET_FIX_PART_LEN, REQUEST_PACKET_FIX_PART_LEN + url_len - 1);
    var payload = packet.slice(REQUEST_PACKET_FIX_PART_LEN + url_len, REQUEST_PACKET_FIX_PART_LEN + url_len + payload_len);

    var req = new wamr_request(mid, String.UTF8.decode(url), action, fmt, payload, payload_len);
    req.sender = sender;

    return req;
}

function pack_response(resp: wamr_response): DataView {
    var len = RESPONSE_PACKET_FIX_PART_LEN + resp.payload_len
    var buf = new ArrayBuffer(len);

    var dataview = new DataView(buf, 0, len);

    dataview.setUint8(0, 1);
    dataview.setUint8(1, u8(resp.status));
    dataview.setUint16(2, u16(resp.fmt));
    dataview.setUint32(4, resp.mid);
    dataview.setUint32(8, resp.receiver);
    dataview.setUint32(12, resp.payload_len)

    if (resp.payload != null) {
        var payload_view = new DataView(resp.payload!);
        for (let i = 0; i < resp.payload_len; i++) {
            dataview.setUint8(i + 16, payload_view.getUint8(i));
        }
    }

    return dataview;
}

function unpack_response(packet: ArrayBuffer, size: i32): wamr_response {
    var dataview = new DataView(packet, 0, size);

    if (dataview.getUint8(0) != 1)
        throw new Error("packet version mismatch");

    if (size < RESPONSE_PACKET_FIX_PART_LEN)
        throw new Error("packet size error");

    var payload_len = dataview.getUint32(12);
    if (size != RESPONSE_PACKET_FIX_PART_LEN + payload_len)
        throw new Error("packet size error");

    var status = dataview.getUint8(1);
    var fmt = dataview.getUint16(2);
    var mid = dataview.getUint32(4);
    var receiver = dataview.getUint32(8);

    var payload = packet.slice(RESPONSE_PACKET_FIX_PART_LEN);

    var resp = new wamr_response(mid, status, fmt, payload, payload_len);
    resp.receiver = receiver;

    return resp;
}

function do_request(req: wamr_request, cb: (resp: wamr_response) => void): void {
    var trans = new wamr_transaction(req.mid, timer.now(), cb);
    var msg = pack_request(req);

    transaction_add(trans);

    wasm_post_request(msg.buffer, msg.byteLength);
}

function do_response(resp: wamr_response): void {
    var msg = pack_response(resp);

    wasm_response_send(msg.buffer, msg.byteLength);
}

var resource_list = new Array<wamr_resource>();
type request_handler_f = (req: wamr_request) => void;

function registe_url_handler(url: string, cb: request_handler_f, type: number): void {
    for (let i = 0; i < resource_list.length; i++) {
        if (resource_list[i].type == type && resource_list[i].url == url) {
            resource_list[i].cb = cb;
            return;
        }
    }

    var res = new wamr_resource(url, type, cb);
    resource_list.push(res);

    if (type == Reg_Request)
        wasm_register_resource(String.UTF8.encode(url));
    else
        wasm_sub_event(String.UTF8.encode(url));
}

function is_event_type(req: wamr_request): bool {
    return req.action == COAP_EVENT;
}

function check_url_start(url: string, leading_str: string): bool {
    return url.split('/')[0] == leading_str.split('/')[0];
}

/* User APIs below */
export function post(url: string, payload: ArrayBuffer, payload_len: number, tag: string,
                     cb: (resp: wamr_response) => void): void {
    var req = new wamr_request(g_mid++, url, COAP_POST, 0, payload, payload_len);

    do_request(req, cb);
}

export function get(url: string, tag: string,
                    cb: (resp: wamr_response) => void): void {
    var req = new wamr_request(g_mid++, url, COAP_GET, 0, new ArrayBuffer(0), 0);

    do_request(req, cb);
}

export function put(url: string, payload: ArrayBuffer, payload_len: number, tag: string,
                    cb: (resp: wamr_response) => void): void {
    var req = new wamr_request(g_mid++, url, COAP_PUT, 0, payload, payload_len);

    do_request(req, cb);
}

export function del(url: string, tag: string,
                    cb: (resp: wamr_response) => void): void {
    var req = new wamr_request(g_mid++, url, COAP_DELETE, 0, new ArrayBuffer(0), 0);

    do_request(req, cb);
}

export function make_response_for_request(req: wamr_request): wamr_response {
    var resp = new wamr_response(req.mid, CoAP_Status.CONTENT_2_05, 0, null, 0);
    resp.receiver = req.sender;

    return resp;
}

export function api_response_send(resp: wamr_response): void {
    do_response(resp);
}

export function register_resource_handler(url: string,
    request_handle: request_handler_f): void {
    registe_url_handler(url, request_handle, Reg_Request);
}

export function publish_event(url: string, fmt: number,
    payload: ArrayBuffer, payload_len: number): void {
    var req = new wamr_request(g_mid++, url, COAP_EVENT, i32(fmt), payload, payload_len);

    var msg = pack_request(req);

    wasm_post_request(msg.buffer, msg.byteLength);
}

export function subscribe_event(url: string, cb: request_handler_f): void {
    registe_url_handler(url, cb, Reg_Event);
}


/* These two APIs are required by wamr runtime,
    use a wrapper to export them in the entry file

    e.g:

    import * as request from '.wamr_app_lib/request'

    // Your code here ...

    export function _on_request(buffer_offset: i32, size: i32): void {
        on_request(buffer_offset, size);
    }

    export function _on_response(buffer_offset: i32, size: i32): void {
        on_response(buffer_offset, size);
    }
*/
export function on_request(buffer_offset: i32, size: i32): void {
    var buffer = new ArrayBuffer(size);
    var dataview = new DataView(buffer);

    for (let i = 0; i < size; i++) {
        dataview.setUint8(i, load<i8>(buffer_offset + i, 0, 1));
    }

    var req = unpack_request(buffer, size);

    var is_event = is_event_type(req);

    for (let i = 0; i < resource_list.length; i++) {
        if ((is_event && resource_list[i].type == Reg_Event)
            || (!is_event && resource_list[i].type == Reg_Request)) {
            if (check_url_start(req.url, resource_list[i].url)) {
                resource_list[i].cb(req);
                return;
            }
        }
    }

    console.log("on_request: exit. no service handler.");
}

export function on_response(buffer_offset: i32, size: i32): void {
    var buffer = new ArrayBuffer(size);
    var dataview = new DataView(buffer);

    for (let i = 0; i < size; i++) {
        dataview.setUint8(i, load<i8>(buffer_offset + i, 0, 1));
    }

    var resp = unpack_response(buffer, size);
    var trans = transaction_find(resp.mid);

    if (trans != null) {
        if (transaction_list.indexOf(trans) == 0) {
            if (transaction_list.length >= 2) {
                var elpased_ms: number, ms_to_expiry: number;
                var now = timer.now();
                if (now < transaction_list[1].time) {
                    elpased_ms = now + (0xFFFFFFFF - transaction_list[1].time) + 1;
                } else {
                    elpased_ms = now - transaction_list[1].time;
                }
                ms_to_expiry = TRANSACTION_TIMEOUT_MS - elpased_ms;
                timer.timer_restart(g_trans_timer, ms_to_expiry);
            } else {
                timer.timer_cancel(g_trans_timer);
            }
        }

        trans.cb(resp);
    }
}
