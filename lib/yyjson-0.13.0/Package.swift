// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "yyjson",
    products: [
        .library(
            name: "yyjson",
            targets: ["yyjson"]
        )
    ],
    traits: [
        .trait(name: "noReader", description: "Omit JSON reader"),
        .trait(name: "noWriter", description: "Omit JSON writer"),
        .trait(name: "noIncrementalReader", description: "Omit incremental reader"),
        .trait(name: "noUtilities", description: "Omit JSON Pointer, Patch, Merge Patch"),
        .trait(
            name: "noFastFloatingPoint",
            description: "Use libc strtod/snprintf"
        ),
        .trait(
            name: "strictStandardJSON",
            description: "Disable non-standard JSON features"
        ),
        .trait(
            name: "noUTF8Validation",
            description: "Skip UTF-8 validation"
        ),
    ],
    targets: [
        .target(
            name: "yyjson",
            path: ".",
            sources: ["src"],
            publicHeadersPath: "src",
            cSettings: [
                .define("YYJSON_DISABLE_READER", to: "1", .when(traits: ["noReader"])),
                .define("YYJSON_DISABLE_WRITER", to: "1", .when(traits: ["noWriter"])),
                .define("YYJSON_DISABLE_INCR_READER", to: "1", .when(traits: ["noIncrementalReader"])),
                .define("YYJSON_DISABLE_UTILS", to: "1", .when(traits: ["noUtilities"])),
                .define("YYJSON_DISABLE_FAST_FP_CONV", to: "1", .when(traits: ["noFastFloatingPoint"])),
                .define("YYJSON_DISABLE_NON_STANDARD", to: "1", .when(traits: ["strictStandardJSON"])),
                .define("YYJSON_DISABLE_UTF8_VALIDATION", to: "1", .when(traits: ["noUTF8Validation"])),
            ]
        )
    ]
)
