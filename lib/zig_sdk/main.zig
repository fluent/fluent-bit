const std = @import("std");

pub const version = "1.0.0";

const c = @cImport({
    @cInclude("fluent-bit/flb_output.h");
});

const le = @cImport({
    @cInclude("fluent-bit/flb_log_event.h");
});

const led = @cImport({
    @cInclude("fluent-bit/flb_log_event_decoder.h");
});

const lee = @cImport({
    @cInclude("fluent-bit/flb_log_event_encoder.h");
});

const d = @cImport({
    @cInclude("fluent-bit/flb_mp_chunk.h");
});

const cv = @cImport({
    @cInclude("cfl/cfl_variant.h");
});

pub const cfl_array = cv.cfl_array;
pub const cfl_kvlist = cv.cfl_kvlist;
pub const cfl_variant = cv.cfl_variant;

pub const CFL_VARIANT_BOOL = cv.CFL_VARIANT_BOOL;
pub const CFL_VARIANT_INT = cv.CFL_VARIANT_INT;
pub const CFL_VARIANT_UINT = cv.CFL_VARIANT_UINT;
pub const CFL_VARIANT_DOUBLE = cv.CFL_VARIANT_DOUBLE;
pub const CFL_VARIANT_NULL = cv.CFL_VARIANT_NULL;
pub const CFL_VARIANT_REFERENCE = cv.CFL_VARIANT_REFERENCE;
pub const CFL_VARIANT_STRING = cv.CFL_VARIANT_STRING;
pub const CFL_VARIANT_BYTES = cv.CFL_VARIANT_BYTES;
pub const CFL_VARIANT_ARRAY = cv.CFL_VARIANT_ARRAY;
pub const CFL_VARIANT_KVLIST = cv.CFL_VARIANT_KVLIST;

pub const ReturnValue = enum {
    Int,
    String,
    Float,
};

fn convert_variant_bool_to_native(value: *zig_sdk.cfl_variant) bool {
    return false;
}

export fn convert_variant_to_native(value: *cfl_variant) ReturnValue {
    //
    //pub const cfl_array = cv.cfl_array;
    //pub const cfl_kvlist = cv.cfl_kvlist;
    //pub const cfl_variant = cv.cfl_variant;
    //

    switch (data.*.type) {
        zig_sdk.CFL_VARIANT_BOOL => {
            return convert_variant_bool_to_native(value.*.data.as_bool);
        },
        zig_sdk.CFL_VARIANT_INT => {},
        zig_sdk.CFL_VARIANT_UINT => {},
        zig_sdk.CFL_VARIANT_DOUBLE => {},
        zig_sdk.CFL_VARIANT_NULL => {},
        zig_sdk.CFL_VARIANT_REFERENCE => {},
        zig_sdk.CFL_VARIANT_STRING => {},
        zig_sdk.CFL_VARIANT_BYTES => {},
        zig_sdk.CFL_VARIANT_ARRAY => {},
        zig_sdk.CFL_VARIANT_KVLIST => {},
    }

    return undefined;
}

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

pub const flb_log_event = c.flb_log_event;

pub const flb_log_event_encoder = lee.flb_log_event_encoder;

pub const flb_log_event_encoder_create = lee.flb_log_event_encoder_create;
pub const flb_log_event_encoder_destroy = lee.flb_log_event_encoder_destroy;

pub const FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2 = le.FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2;

pub const flb_log_event_decoder = led.flb_log_event_decoder;
pub const flb_log_event_decoder_create = led.flb_log_event_decoder_create;
pub const flb_log_event_decoder_destroy = led.flb_log_event_decoder_destroy;
pub const flb_log_event_decoder_next = led.flb_log_event_decoder_next;

pub const FLB_EVENT_DECODER_SUCCESS = led.FLB_EVENT_DECODER_SUCCESS;
pub const FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE = led.FLB_EVENT_DECODER_ERROR_INITIALIZATION_FAILURE;
pub const FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT = led.FLB_EVENT_DECODER_ERROR_INVALID_CONTEXT;
pub const FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT = led.FLB_EVENT_DECODER_ERROR_INVALID_ARGUMENT;
pub const FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE = led.FLB_EVENT_DECODER_ERROR_WRONG_ROOT_TYPE;
pub const FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE = led.FLB_EVENT_DECODER_ERROR_WRONG_ROOT_SIZE;
pub const FLB_EVENT_DECODER_ERROR_WRONG_HEADER_TYPE = led.FLB_EVENT_DECODER_ERROR_WRONG_HEADER_TYPE;
pub const FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE = led.FLB_EVENT_DECODER_ERROR_WRONG_HEADER_SIZE;
pub const FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE = led.FLB_EVENT_DECODER_ERROR_WRONG_TIMESTAMP_TYPE;
pub const FLB_EVENT_DECODER_ERROR_WRONG_METADATA_TYPE = led.FLB_EVENT_DECODER_ERROR_WRONG_METADATA_TYPE;
pub const FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE = led.FLB_EVENT_DECODER_ERROR_WRONG_BODY_TYPE;
pub const FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE = led.FLB_EVENT_DECODER_ERROR_DESERIALIZATION_FAILURE;
pub const FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA = led.FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA;

pub const flb_mp_chunk_record = d.flb_mp_chunk_record;
pub const flb_mp_chunk_record_create = d.flb_mp_chunk_record_create;
pub const flb_mp_chunk_cobj_record_destroy = d.flb_mp_chunk_cobj_record_destroy;
pub const flb_mp_chunk_cobj_record_next = d.flb_mp_chunk_cobj_record_next;

pub const flb_mp_chunk_cobj = d.flb_mp_chunk_cobj;
pub const flb_mp_chunk_cobj_create = d.flb_mp_chunk_cobj_create;
pub const flb_mp_chunk_cobj_destroy = d.flb_mp_chunk_cobj_destroy;
pub const flb_mp_chunk_cobj_encode = d.flb_mp_chunk_cobj_encode;

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
        @ptrCast(@constCast(event_chunk.*.data)),
        event_chunk.*.size,
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
