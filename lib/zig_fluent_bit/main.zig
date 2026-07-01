const std = @import("std");

pub const version = "1.0.0";

pub const Config = @import("config.zig");
pub const Constants = @import("constants.zig");

const Allocator = @import("allocator.zig");
const InputPlugin_ = @import("input_plugin.zig");
const OutputPlugin_ = @import("output_plugin.zig");

pub const NativeInputPluginInstance = InputPlugin_.NativeInputPluginInstance;
pub const NativeOutputPluginInstance = OutputPlugin_.NativeOutputPluginInstance;
pub const OutputPlugin = OutputPlugin_.OutputPlugin;

pub const allocator: std.mem.Allocator = .{
    .ptr = undefined,
    .vtable = &Allocator.vtable,
};
