const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addObject(.{
        .name = "flb-plugin-out_zig_demo",
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();

    const fluent_bit = b.dependency("zig_fluent_bit", .{});
    const msgpack = b.dependency("zig_msgpack", .{});

    lib.root_module.addImport("zig_fluent_bit", fluent_bit.module("zig_fluent_bit"));
    lib.root_module.addImport("zig_msgpack", msgpack.module("msgpack"));

    const install = b.addInstallArtifact(lib, .{
        .dest_dir = .{ .override = .{ .custom = "." } },
        .h_dir = .{ .override = .{ .custom = "." } },
    });

    b.default_step.dependOn(&install.step);
}
