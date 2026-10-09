use std::env;

#[cfg(feature = "zeroparser")]
#[path = "src/zeroparser/proto_build.rs"]
mod zeroparser_proto_build;

fn main() {
    env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    tonic_prost_build::compile_protos("zerobus_service.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));

    #[cfg(feature = "zeroparser")]
    zeroparser_proto_build::compile();
}
