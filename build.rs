use std::path::PathBuf;

const HEADER_CONTENT: &str = "
    #include <linux/blkzoned.h>
    #include <linux/ublk_cmd.h>
";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("ublk_cmd.rs");
    bindgen::Builder::default()
        .header_contents("wrapper.h", HEADER_CONTENT)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .use_core()
        .allowlist_var("UBLK(?:SRV)?_.*")
        .allowlist_type("ublk(?:srv)?_.*|blk_zone.*")
        .prepend_enum_name(false)
        .derive_default(true)
        .generate()
        .expect("failed to bindgen")
        .write_to_file(out_path)
        .expect("failed to write bindgen output");
}
