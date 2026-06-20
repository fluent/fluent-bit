const std = @import("std");

pub const version = "1.0.0";

const Config = @import("config.zig");
const Constants = @import("constants.zig");
const Allocator = @import("allocator.zig");

const NativeInputPluginInstance = @import("input_plugin.zig").NativeInputPluginInstance;

const flb_log_h = @cImport({
    @cInclude("fluent-bit/flb_log.h");
});

const flb_output_h = @cImport({
    @cInclude("fluent-bit/flb_output.h");
});

const flb_output_plugin_h = @cImport({
    @cInclude("fluent-bit/flb_output_plugin.h");
});

const EventChunk = flb_output_h.flb_event_chunk;
const OutputFlush = flb_output_h.flb_output_flush;

pub const NativeOutputPlugin = flb_output_h.flb_output_plugin;
pub const NativeOutputPluginInstance = flb_output_h.flb_output_instance;

const FLB_OUTPUT_RETURN = flb_output_h.flb_output_return_do;

const allocator_: std.mem.Allocator = .{
    .ptr = undefined,
    .vtable = &Allocator.vtable,
};

pub const OutputPlugin = extern struct {
    native_plugin: NativeOutputPlugin = .{},
    name: [*c]const u8,
    description: [*c]const u8,
    initCallback: ?*const fn (ins: *anyopaque, config: *anyopaque, data: ?*anyopaque) callconv(.C) c_int,
    flushCallback: ?*const fn (data: []const u8, tag: []const u8, i_ins: *NativeInputPluginInstance, out_context: ?*anyopaque, config: *Config.Config) anyerror!c_int,
    exitCallback: ?*const fn (data: *anyopaque, config: [*c]Config.Config) callconv(.C) c_int,
    destroyCallback: ?*const fn (plugin: *anyopaque) void,
    workerInitCallback: ?*const fn (context: *anyopaque, config: [*c]Config.Config) c_int,
    workerExitCallback: ?*const fn (context: *anyopaque, config: [*c]Config.Config) c_int,
    notificationCallback: ?*const fn (context: *anyopaque, config: [*c]Config.Config, data: *anyopaque) c_int,

    flags: c_int,
    config_map: [*c]Config.ConfigMap,
    event_type: c_int,

    pub fn setContext(
        instance: *anyopaque,
        context: *anyopaque,
    ) void {
        flb_output_h.flb_output_set_context(@ptrCast(@alignCast(instance)), context);
    }

    pub fn setConfigMap(
        instance: *anyopaque,
        context: *anyopaque,
    ) i32 {
        return flb_output_h.flb_output_config_map_set(@ptrCast(@alignCast(instance)), context);
    }

    fn logPrint(context: [*c]NativeOutputPluginInstance, comptime message_level: i32, message: []const u8) void {
        var local_message: []const u8 = undefined;
        const worker: *flb_log_h.flb_worker = flb_log_h.flb_worker_get();

        if (message.len > 0) {
            local_message = message;
        } else {
            local_message = "\x00";
        }

        if (flb_log_h.flb_log_cache_check_suppress(worker.*.log_cache, @constCast(message.ptr), message.len) == 0) {
            flb_log_h.flb_log_print(
                message_level,
                null,
                0,
                "[output:%s:%s] %s",
                context.*.p.*.name,
                flb_output_h.flb_output_name(context),
                local_message.ptr,
            );
        }
    }

    pub fn logError(context: [*c]NativeOutputPluginInstance, comptime format: []const u8, arguments: anytype) void {
        if (flb_output_plugin_h.flb_log_check_level(context.*.log_level, flb_log_h.FLB_LOG_ERROR) == 0) {
            return;
        }

        var arena = std.heap.ArenaAllocator.init(allocator_);

        defer arena.deinit();

        const allocator = arena.allocator();

        const message = std.fmt.allocPrint(allocator, format, arguments) catch return;

        defer allocator.free(message);
    }

    pub fn logWarning(context: [*c]NativeOutputPluginInstance, comptime format: []const u8, arguments: anytype) void {
        if (flb_output_plugin_h.flb_log_check_level(context.*.log_level, flb_log_h.FLB_LOG_WARN) == 0) {
            return;
        }

        var arena = std.heap.ArenaAllocator.init(allocator_);

        defer arena.deinit();

        const allocator = arena.allocator();

        const message = std.fmt.allocPrint(allocator, format, arguments) catch return;

        defer allocator.free(message);

        logPrint(context, flb_log_h.FLB_LOG_WARN, message);
    }

    pub fn logInfo(context: [*c]NativeOutputPluginInstance, comptime format: []const u8, arguments: anytype) void {
        if (flb_output_plugin_h.flb_log_check_level(context.*.log_level, flb_log_h.FLB_LOG_INFO) == 0) {
            return;
        }

        var arena = std.heap.ArenaAllocator.init(allocator_);

        defer arena.deinit();

        const allocator = arena.allocator();

        const message = std.fmt.allocPrint(allocator, format, arguments) catch return;

        defer allocator.free(message);

        logPrint(context, flb_log_h.FLB_LOG_INFO, message);
    }

    pub fn logDebug(context: [*c]NativeOutputPluginInstance, comptime format: []const u8, arguments: anytype) void {
        if (flb_output_plugin_h.flb_log_check_level(context.*.log_level, flb_log_h.FLB_LOG_DEBUG) == 0) {
            return;
        }

        var arena = std.heap.ArenaAllocator.init(allocator_);

        defer arena.deinit();

        const allocator = arena.allocator();

        const message = std.fmt.allocPrint(allocator, format, arguments) catch return;

        defer allocator.free(message);

        logPrint(context, flb_log_h.FLB_LOG_DEBUG, message);
    }

    pub fn logTrace(context: [*c]NativeOutputPluginInstance, comptime format: []const u8, arguments: anytype) void {
        if (flb_output_plugin_h.flb_log_check_level(context.*.log_level, flb_log_h.FLB_LOG_TRACE) == 0) {
            return;
        }

        var arena = std.heap.ArenaAllocator.init(allocator_);

        defer arena.deinit();

        const allocator = arena.allocator();

        const message = std.fmt.allocPrint(allocator, format, arguments) catch return;

        defer allocator.free(message);

        logPrint(context, flb_log_h.FLB_LOG_TRACE, message);
    }
};

fn flb_zig_output_plugin_cb_init(
    ins: [*c]NativeOutputPluginInstance,
    config: [*c]Config.Config,
    data: ?*anyopaque,
) callconv(.C) c_int {
    const zig_instance: *OutputPlugin = @ptrCast(ins.*.p);

    return zig_instance.initCallback.?(ins, config, data);
}

fn flb_zig_output_plugin_cb_flush(
    event_chunk: [*c]EventChunk,
    flush: [*c]OutputFlush,
    input_instance: [*c]NativeInputPluginInstance,
    out_context: ?*anyopaque,
    config: [*c]Config.Config,
) callconv(.C) noreturn {
    const zig_instance: *OutputPlugin = @ptrCast(flush.*.o_ins.*.p);
    const data_buffer: [*c]const u8 = @ptrCast(@constCast(event_chunk.*.data));
    const data_slice: []const u8 = data_buffer[0..event_chunk.*.size];
    const tag_length = flb_output_h.flb_sds_len(event_chunk.*.tag);
    const tag_buffer: [*c]const u8 = @ptrCast(@constCast(event_chunk.*.tag));
    const tag_slice: []const u8 = tag_buffer[0..tag_length];

    const result: c_int = zig_instance.flushCallback.?(
        data_slice,
        tag_slice,
        input_instance,
        out_context,
        config,
    ) catch |error_code| {
        std.debug.print("Error : {any}\n", .{error_code});
        std.os.linux.exit(1);
    };

    FLB_OUTPUT_RETURN(result);

    unreachable;
}

export fn flb_zig_native_output_plugin_init(
    zig_instance: *OutputPlugin,
) [*c]NativeOutputPlugin {
    // This has to be allocated in this particular way to ensure it's cleanly
    // handed over to the native system for cleanup
    const result: *OutputPlugin = @ptrCast(
        @alignCast(
            flb_output_h.flb_calloc(
                1,
                @sizeOf(OutputPlugin),
            ),
        ),
    );

    result.* = zig_instance.*;

    result.*.native_plugin.flags = zig_instance.*.flags;
    result.*.native_plugin.event_type = zig_instance.*.event_type;
    result.*.native_plugin.config_map = @ptrCast(zig_instance.*.config_map);

    result.*.native_plugin.name = @constCast(zig_instance.*.name);
    result.*.native_plugin.description = @constCast(zig_instance.*.description);

    result.*.native_plugin.cb_init = @ptrCast(&flb_zig_output_plugin_cb_init);
    result.*.native_plugin.cb_flush = @ptrCast(&flb_zig_output_plugin_cb_flush);
    result.*.native_plugin.cb_exit = @ptrCast(result.*.exitCallback);

    result.*.native_plugin.cb_destroy = @ptrCast(result.*.destroyCallback);
    result.*.native_plugin.cb_worker_init = @ptrCast(result.*.workerInitCallback);
    result.*.native_plugin.cb_worker_exit = @ptrCast(result.*.workerExitCallback);
    result.*.native_plugin.cb_notification = @ptrCast(result.*.notificationCallback);

    return @ptrCast(result);
}
