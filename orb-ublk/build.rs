use std::path::PathBuf;

const HEADER_CONTENT: &str = "
    #include <linux/blkzoned.h>
    #include <linux/ublk_cmd.h>

    /* Workaround: https://github.com/rust-lang/rust-bindgen/issues/753#issuecomment-459851952 */
    #define MARK_FIX_753(req_name) const __u32 Fix753_##req_name = req_name;
    MARK_FIX_753(UBLK_U_CMD_GET_QUEUE_AFFINITY)
    MARK_FIX_753(UBLK_U_CMD_GET_DEV_INFO)
    MARK_FIX_753(UBLK_U_CMD_ADD_DEV)
    MARK_FIX_753(UBLK_U_CMD_DEL_DEV)
    MARK_FIX_753(UBLK_U_CMD_START_DEV)
    MARK_FIX_753(UBLK_U_CMD_STOP_DEV)
    MARK_FIX_753(UBLK_U_CMD_SET_PARAMS)
    MARK_FIX_753(UBLK_U_CMD_GET_PARAMS)
    MARK_FIX_753(UBLK_U_CMD_START_USER_RECOVERY)
    MARK_FIX_753(UBLK_U_CMD_END_USER_RECOVERY)
    MARK_FIX_753(UBLK_U_CMD_GET_DEV_INFO2)
    MARK_FIX_753(UBLK_U_CMD_GET_FEATURES)
";

#[derive(Debug)]
struct PreserveIoctlCallback;

impl bindgen::callbacks::ParseCallbacks for PreserveIoctlCallback {
    fn item_name(&self, original_item_name: &str) -> Option<String> {
        Some(original_item_name.trim_start_matches("Fix753_").to_owned())
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out_path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("ublk_cmd.rs");
    bindgen::Builder::default()
        .header_contents("wrapper.h", HEADER_CONTENT)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(PreserveIoctlCallback))
        .use_core()
        .allowlist_var("UBLK(?:SRV)?_.*|Fix753_.*")
        .allowlist_type("ublk(?:srv)?_.*|blk_zone(?:_type|_cond|)")
        // `blk_zone_{type,cond}` need no extra prefixes.
        .prepend_enum_name(false)
        .derive_default(true)
        .layout_tests(false)
        .generate()
        .expect("failed to bindgen")
        .write_to_file(out_path)
        .expect("failed to write bindgen output");
}