fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "macos" {
        link_macos_endpoint_security();
    }
}

fn link_macos_endpoint_security() {
    let output = std::process::Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .expect("xcrun failed")
        .stdout;
    let sdk_raw = String::from_utf8(output).unwrap();
    let sdk = sdk_raw.trim();

    println!("cargo:rustc-link-search=native={sdk}/usr/lib");
    println!("cargo:rustc-link-lib=dylib=EndpointSecurity");
    println!("cargo:rustc-link-lib=dylib=bsm");
}
