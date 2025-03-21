const std = @import("std");
const zig_sdk = @import("zigsdk");

pub const plugin_context = extern struct {
    format: [*c]const u8,
};

var testx: *plugin_context = undefined;

fn cb_init(ins: *anyopaque, config: *anyopaque, data: ?*anyopaque) callconv(.C) c_int {
    //_ = ins;
    _ = config;
    _ = data;

    var allocator = std.heap.page_allocator;

    const context = allocator.create(plugin_context) catch {
        return zig_sdk.FLB_ERROR;
    };

    _ = zig_sdk.flb_output_config_map_set(@ptrCast(@alignCast(ins)), context);

    zig_sdk.flb_output_set_context(@ptrCast(@alignCast(ins)), context);

    std.debug.print("cb_init, context = {*}\n", .{context});

    std.debug.print("Format = {s}\n", .{context.format});

    return zig_sdk.FLB_OK;
}

fn cb_flush(data: *const anyopaque, bytes: usize, tag: [*c]const u8, tag_len: usize, i_ins: *zig_sdk.flb_input_instance, context: ?*anyopaque, config: *zig_sdk.flb_config) callconv(.C) c_int {
    _ = data;
    _ = bytes;
    _ = i_ins;
    //_ = tag;
    _ = tag_len;
    _ = config;

    // Your flush logic here
    //const slice = @ptrCast([*]const u8, data)[0..bytes];
    //const tag_slice = @ptrCast([*]const u8, tag)[0..tag_len];
    //std.debug.print("Plugin flushed: {s} {s}\n", .{ slice, tag_slice });
    //std.debug.print("Flushing chunk with size: {}\n", .{chunk.*.size});
    std.debug.print("FLUSH CALLBACK FOR TAG {s}\n", .{tag});
    std.debug.print("cb_flush, context = {any}\n", .{context});


pub const flb_log_event_decoder = c.flb_log_event_decoder;
pub const flb_log_event_decoder_create = c.flb_log_event_decoder_create;
pub const flb_log_event_decoder_destroy = c.flb_log_event_decoder_destroy;
pub const flb_log_event_decoder_next = c.flb_log_event_decoder_next;


    return zig_sdk.FLB_OK;
}

fn cb_exit(context: *anyopaque, config: [*c]zig_sdk.flb_config) callconv(.C) c_int {
    //const temp: *anyopaque = context.*.?;
    //const temp: *plugin_context = @ptrCast(@alignCast(context));
    _ = config;

    std.debug.print("Plugin exited\n", .{});
    std.debug.print("cb_exit, context = {any}\n", .{context});

    //defer std.heap.page_allocator.free(&tempb);

    return zig_sdk.FLB_OK;
}

const config_map: [2]zig_sdk.flb_config_map = .{
    .{
        .type = zig_sdk.FLB_CONFIG_MAP_STR,
        .name = @constCast("format\x00"),
        .def_value = null,
        .flags = 0,
        .set_property = zig_sdk.FLB_TRUE,
        .offset = @offsetOf(plugin_context, "format"),
        .desc = @constCast("test\x00"),
    },
    .{ .type = 0 },
};

export const out_zig_test_1_plugin = zig_sdk.flb_zig_output_plugin{
    .name = "out_zig_test_1\x00",
    .description = "Prints events to STDOUT\x00",
    .cb_init = cb_init,
    .cb_flush = cb_flush,
    .cb_exit = cb_exit,
    .flags = 0,
    .config_map = @constCast(&config_map),
};
