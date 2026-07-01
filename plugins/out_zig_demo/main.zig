const builtin = @import("builtin");
const std = @import("std");
const fluent_bit = @import("zig_fluent_bit");
const msgpack = @import("zig_msgpack");

const packer_buffer_type = std.io.FixedBufferStream([]u8);

const pack = msgpack.Pack(
    *packer_buffer_type,
    *packer_buffer_type,
    packer_buffer_type.WriteError,
    packer_buffer_type.ReadError,
    packer_buffer_type.write,
    packer_buffer_type.read,
);

pub const PluginContext = extern struct {
    format: [*c]const u8,
    instance: [*c]fluent_bit.NativeOutputPluginInstance,
};

pub const Timestamp = struct {
    seconds: i64,
    nanoseconds: u32,

    pub fn decodeExt(data: []u8) Timestamp {
        const components = std.mem.bytesAsSlice(u32, data);

        return Timestamp{
            .seconds = std.mem.toNative(u32, components[0], std.builtin.Endian.big),
            .nanoseconds = std.mem.toNative(u32, components[1], std.builtin.Endian.big),
        };
    }
};

fn init(ins: *anyopaque, config: *anyopaque, data: ?*anyopaque) callconv(.C) c_int {
    _ = data;
    _ = config;

    const allocator = fluent_bit.allocator;

    const context = allocator.create(PluginContext) catch {
        return fluent_bit.Constants.FLB_ERROR;
    };

    context.instance = @ptrCast(@alignCast(ins));

    _ = fluent_bit.OutputPlugin.setConfigMap(ins, context);

    fluent_bit.OutputPlugin.setContext(ins, context);

    fluent_bit.OutputPlugin.logInfo(context.instance, "init", .{});

    return fluent_bit.Constants.FLB_OK;
}

fn flush(
    data: []const u8,
    tag: []const u8,
    i_ins: *fluent_bit.NativeInputPluginInstance,
    context_: ?*anyopaque,
    config: *fluent_bit.Config.Config,
) !c_int {
    _ = tag;
    _ = i_ins;
    _ = config;

    const context: *PluginContext = @ptrCast(@alignCast(context_));

    var read_buffer = std.io.fixedBufferStream(@constCast(data));

    const packer_context = pack.init(
        undefined,
        &read_buffer,
    );

    const allocator = fluent_bit.allocator;

    const event = try packer_context.read(allocator);
    defer event.free(allocator);

    const header = try event.getArrElement(0);
    const body = try event.getArrElement(1);
    const timestamp = try header.getArrElement(0);
    const metadata = try header.getArrElement(1);
    const timestamp_ = Timestamp.decodeExt(timestamp.ext.data);

    fluent_bit.OutputPlugin.logInfo(context.instance, "flush", .{});

    fluent_bit.OutputPlugin.logInfo(context.instance, "TS : {}.{}", .{ timestamp_.seconds, timestamp_.nanoseconds });
    fluent_bit.OutputPlugin.logInfo(context.instance, "META : {any}", .{metadata});
    fluent_bit.OutputPlugin.logInfo(context.instance, "BODY : {any}", .{body});
    fluent_bit.OutputPlugin.logInfo(context.instance, "", .{});

    return fluent_bit.Constants.FLB_OK;
}

fn exit(context_: *anyopaque, config: [*c]fluent_bit.Config.Config) callconv(.C) c_int {
    _ = config;

    const allocator = fluent_bit.allocator;
    const context: *PluginContext = @ptrCast(@alignCast(context_));

    fluent_bit.OutputPlugin.logInfo(context.*.instance, "exit", .{});

    allocator.destroy(context);

    return fluent_bit.Constants.FLB_OK;
}

const config_map: [2]fluent_bit.Config.ConfigMap = .{
    .{
        .type = fluent_bit.Config.FLB_CONFIG_MAP_STR,
        .name = @constCast("format"),
        .def_value = null,
        .flags = 0,
        .set_property = fluent_bit.Constants.FLB_TRUE,
        .offset = @offsetOf(PluginContext, "format"),
        .desc = @constCast("test"),
    },
    .{ .type = 0 },
};

export const out_zig_demo_plugin = fluent_bit.OutputPlugin{
    .name = "out_zig_demo",
    .description = "Zig demo plugin",
    .initCallback = init,
    .flushCallback = flush,
    .exitCallback = exit,
    .destroyCallback = undefined,
    .workerInitCallback = undefined,
    .workerExitCallback = undefined,
    .notificationCallback = undefined,
    .flags = 0,
    .event_type = fluent_bit.Constants.FLB_OUTPUT_LOGS,
    .config_map = @constCast(&config_map),
};
