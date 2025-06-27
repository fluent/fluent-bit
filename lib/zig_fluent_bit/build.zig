const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zig_fluent_bit", .{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "zig_fluent_bit",
        .root_module = mod,
        .root_source_file = b.path("main.zig"),
    });

    lib.linkLibC();

    var transient_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer transient_arena.deinit();
    const transient_allocator = transient_arena.allocator();

    const include_directories = std.process.getEnvVarOwned(transient_allocator, "FLB_ZIG_BUILD_INCLUDE_DIRECTORIES") catch |err| {
        if (err == error.EnvironmentVariableNotFound) {
            std.debug.print("Required environment variable missing : FLB_ZIG_BUILD_INCLUDE_DIRECTORIES\n", .{});

            return;
        }

        return;
    };

    defer transient_allocator.free(include_directories);

    var iterator = std.mem.splitSequence(u8, include_directories, ";");

    while (iterator.next()) |include_directory| {
        lib.addIncludePath(.{ .cwd_relative = include_directory });
    }

    const install = b.addInstallArtifact(lib, .{
        .dest_dir = .{ .override = .{ .custom = "." } },
        .h_dir = .{ .override = .{ .custom = "." } },
    });

    b.default_step.dependOn(&install.step);
}
