fn main() {
    let sdk = std::process::Command::new("xcrun")
        .args(["--show-sdk-path"])
        .output()
        .expect("xcrun failed")
        .stdout;
    let sdk = String::from_utf8(sdk).unwrap();
    let sdk = sdk.trim();

    println!("cargo:rustc-link-search=native={sdk}/usr/lib");
    println!("cargo:rustc-link-lib=dylib=EndpointSecurity");
    println!("cargo:rustc-link-lib=dylib=bsm");
}
