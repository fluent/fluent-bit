const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zigsdk", .{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "zigsdk",
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

    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/build/lib/cprofiles/include/" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/build/lib/nghttp2/lib/includes/" });
    //
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/include" });
    //
    //    // Add bundled library include paths
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/cfl/lib/xxhash" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/cfl/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/fluent-otel-proto/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/cmetrics/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/ctraces/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/cprofiles/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/flb_libco/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/rbtree/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/mpack-amalgamation-1.1.1/src" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/msgpack-c/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/nghttp2/lib/includes" });
    //
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/avro/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/chunkio/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/luajit-04dca791/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/monkey/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/jsmn/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/sqlite-amalgamation-3450200" }); // SQLite includes are usually in root
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/jansson-e23f558/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/onigmo/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/mpack-amalgamation-1.1.1/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/miniz/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/tutf8e/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/c-ares-1.34.4/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/snappy-fef67ac/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/librdkafka-2.4.0/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/lwrb/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/wasm-micro-runtime-WAMR-1.3.3/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/zstd-1.5.7/include" });
    //
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/monkey/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/build/lib/monkey/include" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/build/lib/monkey/include/monkey" });
    //
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/flb_libco/" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/cfl/include/" });
    //    lib.addIncludePath(.{ .cwd_relative = "/Users/leonardo/Work/Calyptia/fluent-bit/lib/xxh3/" });

    const install = b.addInstallArtifact(lib, .{
        .dest_dir = .{ .override = .{ .custom = "." } },
        .h_dir = .{ .override = .{ .custom = "." } },
    });

    b.default_step.dependOn(&install.step);
}
