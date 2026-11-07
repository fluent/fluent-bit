// SPDX-License-Identifier: Apache-2.0
#![no_std]

use core::panic::PanicInfo;

// This example targets wasm32: values are linear-memory offsets, not host pointers.
fn value_length(value: *const u8, length: u32) -> u64 {
    ((length as u64) << 32) | (value as u32 as u64)
}

// Borrow the record buffer. Fluent Bit copies it before releasing the input.
#[no_mangle]
pub extern "C" fn filter_v2(
    _tag: *const u8,
    _tag_length: u32,
    _seconds: u32,
    _nanoseconds: u32,
    record: *const u8,
    record_length: u32,
) -> u64 {
    value_length(record, record_length)
}

// Module-owned static storage remains valid after the exported function returns.
// This MessagePack map is {"n": 0, "s": "a\x00b"}.
static BINARY_BODY: [u8; 10] = [0x82, 0xa1, b'n', 0, 0xa1, b's', 0xa3, b'a', 0, b'b'];

#[no_mangle]
pub extern "C" fn filter_binary_v2(
    _tag: *const u8,
    _tag_length: u32,
    _seconds: u32,
    _nanoseconds: u32,
    _record: *const u8,
    _record_length: u32,
) -> u64 {
    value_length(BINARY_BODY.as_ptr(), BINARY_BODY.len() as u32)
}

#[no_mangle]
pub extern "C" fn filter_drop_v2(
    _tag: *const u8,
    _tag_length: u32,
    _seconds: u32,
    _nanoseconds: u32,
    _record: *const u8,
    _record_length: u32,
) -> u64 {
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
