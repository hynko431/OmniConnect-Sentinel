fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = "proto/sentinel_cdr.proto";
    println!("cargo:rerun-if-changed={}", proto_file);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&[proto_file], &["proto"])?;

    Ok(())
}
