const std = @import("std");

pub const version = "1.0.0";

const c = @cImport({
    @cInclude("fluent-bit/flb_output.h");
});

pub const FLB_TRUE = 1;
pub const FLB_FALSE = 0;

pub const FLB_CONFIG_MAP_STR = c.FLB_CONFIG_MAP_STR;
pub const FLB_CONFIG_MAP_STR_PREFIX = c.FLB_CONFIG_MAP_STR_PREFIX;
pub const FLB_CONFIG_MAP_INT = c.FLB_CONFIG_MAP_INT;
pub const FLB_CONFIG_MAP_BOOL = c.FLB_CONFIG_MAP_BOOL;
pub const FLB_CONFIG_MAP_DOUBLE = c.FLB_CONFIG_MAP_DOUBLE;
pub const FLB_CONFIG_MAP_SIZE = c.FLB_CONFIG_MAP_SIZE;
pub const FLB_CONFIG_MAP_TIME = c.FLB_CONFIG_MAP_TIME;

pub const FLB_OK = c.FLB_OK;
pub const FLB_RETRY = c.FLB_RETRY;
pub const FLB_ERROR = c.FLB_ERROR;

//pub const flb_config = extern struct {
//    name: [*c]const u8,
//};
//
//pub const flb_output_instance = extern struct {
//    name: [*c]const u8,
//};

//struct flb_output_plugin {
//    ///*
//    // * a 'mask' to define what kind of data the plugin can manage:
//    // *
//    // *  - FLB_OUTPUT_LOGS
//    // *  - FLB_OUTPUT_METRICS
//    // */
//    event_type: c_int;
//
//    ///*
//    // * The type defines if this is a core-based plugin or it's handled by
//    // * some specific proxy.
//    // */
//    type: c_int;
//    proxy: *anyopaque;
//
//    flags: c_int;
//
//    ///* The plugin name */
//    name: [*c]const u8;
//
//    ///* Plugin description */
//    *description: [*c]const u8;
//
//    config_map: *anyopaque;
//
//    host: c.flb_net_host;
//
//    ///* Initalization */
//    cb_init: ?*const fn (ins: *anyopaque, config: *anyopaque, data: ?*anyopaque) callconv(.C) c_int,
//
//    ///* Pre run */
//    //int (*cb_pre_run) (void *, struct flb_config *);
//    cb_pre_run: ?*const fn (ins: *anyopaque, config: *anyopaque) callconv(.C) c_int,
//
//    ///* Flush callback */
//    //void (*cb_flush) (struct flb_event_chunk *,
//    //                  struct flb_output_flush *,
//    //                  struct flb_input_instance *,
//    //                  void *,
//    //                  struct flb_config *);
//
//    cb_flush: ?*const fn (chunk: *anyopaque, flush: *anyopaque, ins: *anyopaque, data: *anyopaque, config: *anyopaque) callconv(.C) anyopaque,
//
//    ///* Exit */
//    //int (*cb_exit) (void *, struct flb_config *);
//    cb_exit: ?*const fn (ins: *anyopaque, config: *anyopaque) callconv(.C) c_int,
//
//    ///* Destroy */
//    //void (*cb_destroy) (struct flb_output_plugin *);
//    cb_destroy: ?*const fn (ins: *anyopaque) callconv(.C) anyopaque,
//
//    ///* Default number of worker threads */
//    workers: c_int;
//
//    //int (*cb_worker_init) (void *, struct flb_config *);
//    cb_worker_init: ?*const fn (ins: *anyopaque, config: *anyopaque) callconv(.C) c_int,
//    //int (*cb_worker_exit) (void *, struct flb_config *);
//    cb_worker_exit: ?*const fn (ins: *anyopaque, config: *anyopaque) callconv(.C) c_int,
//
//    ///* Notification: this callback will be invoked anytime a notification is received*/
//    //int (*cb_notification) (struct flb_output_instance *, struct flb_config *, void *);
//    cb_notification: ?*const fn (ins: *anyopaque, config: *anyopaque, data: *anyopaque) callconv(.C) c_int,
//
//    ///* Tests */
//    //struct flb_test_out_formatter test_formatter;
//    //struct flb_test_out_response test_response;
//
//    ///* Link to global list from flb_config->outputs */
//    //struct mk_list _head;
//};
//
//pub const flb_output_plugin = extern struct {
//    name: [*c]const u8,
//    description: [*c]const u8,
//    cb_init: ?*const fn (ins: *anyopaque, config: *anyopaque, data: ?*anyopaque) callconv(.C) c_int,
//    // cb_flush: ?*const fn (data: *const anyopaque, bytes: usize, tag: [*c]const u8, tag_len: c_int, i_ins: *c.flb_input_instance, out_context: ?*anyopaque, config: *c.flb_config) callconv(.C) c_int,
//    // cb_exit: ?*const fn (data: ?*anyopaque) callconv(.C) c_int,
//    flags: c_int,
//};

pub const flb_config_map = c.flb_config_map;
pub const flb_event_chunk = c.flb_event_chunk;
pub const flb_output_flush = c.flb_output_flush;

pub const flb_config = c.flb_config;

pub const flb_input_instance = c.flb_input_instance;

pub const flb_output_plugin = c.flb_output_plugin;
pub const flb_output_instance = c.flb_output_instance;

pub const flb_output_config_map_set = c.flb_output_config_map_set;

pub const flb_output_set_context = c.flb_output_set_context;

pub const FLB_OUTPUT_RETURN = c.flb_output_return_do;

pub const flb_log_event_decoder = c.flb_log_event_decoder;
pub const flb_log_event_decoder_create = c.flb_log_event_decoder_create;
pub const flb_log_event_decoder_destroy = c.flb_log_event_decoder_destroy;
pub const flb_log_event_decoder_next = c.flb_log_event_decoder_next;

pub const flb_zig_output_plugin = extern struct {
    native_plugin: flb_output_plugin = .{},
    name: [*c]const u8,
    description: [*c]const u8,
    cb_init: ?*const fn (ins: *anyopaque, config: *anyopaque, data: ?*anyopaque) callconv(.C) c_int,
    cb_flush: ?*const fn (data: *const anyopaque, bytes: usize, tag: [*c]const u8, tag_len: usize, i_ins: *flb_input_instance, out_context: ?*anyopaque, config: *flb_config) callconv(.C) c_int,
    cb_exit: ?*const fn (data: *anyopaque, config: [*c]flb_config) callconv(.C) c_int,
    flags: c_int,
    config_map: [*c]c.flb_config_map,
};

pub fn flb_zig_output_plugin_cb_init(
    ins: [*c]flb_output_instance,
    config: [*c]flb_config,
    data: ?*anyopaque,
) callconv(.C) c_int {
    const zig_instance: *flb_zig_output_plugin = @ptrCast(ins.*.p);

    return zig_instance.cb_init.?(ins, config, data);
}

// This is not possible
//
//pub fn flb_zig_output_plugin_cb_exit(
//    data: ?*anyopaque,
//    config: [*c]flb_config,
//) callconv(.C) c_int {
//    const zig_instance: *flb_zig_output_plugin = @ptrCast(ins.*.p);
//
//    return zig_instance.cb_init.?(ins, config, data);
//}

fn flb_zig_output_plugin_cb_flush(
    event_chunk: [*c]flb_event_chunk,
    flush: [*c]flb_output_flush,
    input_instance: [*c]flb_input_instance,
    out_context: ?*anyopaque,
    config: [*c]flb_config,
) callconv(.C) noreturn {
    const zig_instance: *flb_zig_output_plugin = @ptrCast(flush.*.o_ins.*.p);
    var result: c_int = FLB_ERROR;

    result = zig_instance.cb_flush.?(
        undefined,
        undefined,
        event_chunk.*.tag,
        c.flb_sds_len(event_chunk.*.tag),
        input_instance,
        out_context,
        config,
    );

    FLB_OUTPUT_RETURN(result);

    unreachable;
}

export fn flb_zig_native_output_plugin_init(
    zig_instance: *flb_zig_output_plugin,
) [*c]flb_output_plugin {
    var result: *flb_zig_output_plugin = undefined;

    result = @ptrCast(@alignCast(c.flb_calloc(1, @sizeOf(flb_zig_output_plugin))));

    result.* = zig_instance.*;

    result.*.native_plugin.flags = zig_instance.*.flags;
    result.*.native_plugin.config_map = zig_instance.*.config_map;

    result.*.native_plugin.name = @constCast(zig_instance.*.name);
    result.*.native_plugin.description = @constCast(zig_instance.*.description);

    result.*.native_plugin.cb_init = flb_zig_output_plugin_cb_init;
    result.*.native_plugin.cb_flush = flb_zig_output_plugin_cb_flush;
    result.*.native_plugin.cb_exit = @ptrCast(result.*.cb_exit);

    return @ptrCast(result);
}
