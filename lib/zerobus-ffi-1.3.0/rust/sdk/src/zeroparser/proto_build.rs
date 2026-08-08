//! Compiles the proto fixtures used by zeroparser's integration tests and benches.
//!
//! Included as a module of the SDK's build script via `#[path]` from
//! `rust/sdk/build.rs` (and only when the `zeroparser` feature is enabled).

use std::env;
use std::path::PathBuf;

pub fn compile() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    prost_build::Config::new()
        .out_dir(&out_dir)
        .file_descriptor_set_path(out_dir.join("e2e_descriptor_set.bin"))
        .compile_protos(
            &[
                "src/zeroparser/tests/proto/test_proto2.proto",
                "src/zeroparser/tests/proto/test_proto3.proto",
            ],
            &["src/zeroparser/tests/proto"],
        )
        .expect("failed to compile zeroparser e2e protos");

    prost_build::Config::new()
        .file_descriptor_set_path(out_dir.join("bench_descriptor_set.bin"))
        .compile_protos(
            &[
                "src/zeroparser/benches/proto/air_quality.proto",
                "src/zeroparser/benches/proto/wide_schema.proto",
                "src/zeroparser/benches/proto/supported_nullable_types.proto",
            ],
            &["src/zeroparser/benches/proto"],
        )
        .expect("failed to compile zeroparser bench protos");

    println!("cargo:rerun-if-changed=src/zeroparser/tests/proto");
    println!("cargo:rerun-if-changed=src/zeroparser/benches/proto");
}
