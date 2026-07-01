const std = @import("std");

pub const version = "1.0.0";

const flb_macros_h = @cImport({
    @cInclude("fluent-bit/flb_macros.h");
});

const flb_output_h = @cImport({
    @cInclude("fluent-bit/flb_output.h");
});

pub const FLB_TRUE = 1;
pub const FLB_FALSE = 0;

pub const FLB_OK = flb_macros_h.FLB_OK;
pub const FLB_RETRY = flb_macros_h.FLB_RETRY;
pub const FLB_ERROR = flb_macros_h.FLB_ERROR;

pub const FLB_OUTPUT_LOGS = flb_output_h.FLB_OUTPUT_LOGS;
pub const FLB_OUTPUT_METRICS = flb_output_h.FLB_OUTPUT_METRICS;
pub const FLB_OUTPUT_TRACES = flb_output_h.FLB_OUTPUT_TRACES;
pub const FLB_OUTPUT_BLOBS = flb_output_h.FLB_OUTPUT_BLOBS;
pub const FLB_OUTPUT_PROFILES = flb_output_h.FLB_OUTPUT_PROFILES;
