const std = @import("std");

pub const version = "1.0.0";

const flb_config_map_h = @cImport({
    @cInclude("fluent-bit/flb_config_map.h");
});

const flb_config_h = @cImport({
    @cInclude("fluent-bit/flb_config.h");
});

pub const FLB_CONFIG_MAP_STR = flb_config_map_h.FLB_CONFIG_MAP_STR;
pub const FLB_CONFIG_MAP_STR_PREFIX = flb_config_map_h.FLB_CONFIG_MAP_STR_PREFIX;
pub const FLB_CONFIG_MAP_INT = flb_config_map_h.FLB_CONFIG_MAP_INT;
pub const FLB_CONFIG_MAP_BOOL = flb_config_map_h.FLB_CONFIG_MAP_BOOL;
pub const FLB_CONFIG_MAP_DOUBLE = flb_config_map_h.FLB_CONFIG_MAP_DOUBLE;

pub const FLB_CONFIG_MAP_SIZE = flb_config_map_h.FLB_CONFIG_MAP_SIZE;
pub const FLB_CONFIG_MAP_TIME = flb_config_map_h.FLB_CONFIG_MAP_TIME;

pub const Config = flb_config_h.flb_config;
pub const ConfigMap = flb_config_map_h.flb_config_map;
