const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const assert = std.debug.assert;
const math = std.math;

const flb_mem_h = @cImport({
    @cInclude("fluent-bit/flb_mem.h");
});

pub const vtable: Allocator.VTable = .{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

pub const Error = Allocator.Error;

const max_usize = math.maxInt(usize);
const ushift = math.Log2Int(usize);

fn alloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, return_address: usize) ?[*]u8 {
    _ = ctx;
    _ = return_address;
    const actual_len = @max(len +| @sizeOf(usize), alignment.toByteUnits());

    return @ptrCast(flb_mem_h.flb_calloc(1, actual_len));
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    return_address: usize,
) bool {
    _ = ctx;
    _ = buf;
    _ = alignment;
    _ = new_len;
    _ = return_address;

    return false;
}

fn remap(
    context: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    _ = context;
    _ = return_address;
    const buf_align = alignment.toByteUnits();
    const new_actual_len = @max(new_len +| @sizeOf(usize), buf_align);

    return @ptrCast(flb_mem_h.flb_realloc(memory.ptr, new_actual_len));
}

fn free(
    ctx: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    return_address: usize,
) void {
    _ = ctx;
    _ = alignment;
    _ = return_address;

    flb_mem_h.flb_free(buf.ptr);
}

pub const allocator: std.mem.Allocator = .{
    .ptr = undefined,
    .vtable = &Allocator.vtable,
};

const test_ally: Allocator = .{
    .ptr = undefined,
    .vtable = &vtable,
};

test "standard allocator tests" {
    try std.heap.testAllocator(test_ally);
    try std.heap.testAllocatorAligned(test_ally);
}
