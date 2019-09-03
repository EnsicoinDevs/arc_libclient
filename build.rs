extern crate tower_grpc_build;

fn main() {
    tower_grpc_build::Config::new()
        .enable_server(false)
        .enable_client(true)
        .build(&["ensicoin-proto/node.proto"], &["ensicoin-proto"])
        .unwrap_or_else(|e| panic!("protobuf compilation failed: {}", e));
}
