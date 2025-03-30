const std = @import("std");

pub const version = "1.0.0";

const flb_input_h = @cImport({
    @cInclude("fluent-bit/flb_input.h");
});

pub const NativeInputPlugin = flb_input_h.flb_input_plugin;
pub const NativeInputPluginInstance = flb_input_h.flb_input_instance;
