const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addObject(.{
        .name = "flb-plugin-out_zig_test_1",
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();

    const my_package_dep = b.dependency("zigsdk", .{});
    lib.root_module.addImport("zigsdk", my_package_dep.module("zigsdk"));

    //const msgpack = b.dependency("zig_msgpack", .{
    //    .target = target,
    //    .optimize = optimize,
    //});

    // add module
    //lib.root_module.addImport("zig_msgpack", msgpack.module("msgpack"));

    const install = b.addInstallArtifact(lib, .{
        .dest_dir = .{ .override = .{ .custom = "." } },
        .h_dir = .{ .override = .{ .custom = "." } },
    });

    b.default_step.dependOn(&install.step);
}
