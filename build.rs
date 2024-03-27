#[cfg(feature = "completion")]
#[allow(dead_code)]
#[path = "src/cli.rs"]
mod cli;

fn main() {
    // Do NOT rerun on src changes.
    println!("cargo:rerun-if-changed=build.rs");

    println!("cargo:rerun-if-env-changed=CFG_RELEASE");
    if std::env::var("CFG_RELEASE").is_err() {
        let version = std::env::var("CARGO_PKG_VERSION").unwrap();
        println!("cargo:rustc-env=CFG_RELEASE={version}");
    }

    #[cfg(feature = "completion")]
    {
        use clap::ValueEnum;
        use clap_complete::{generate_to, shells::Shell};

        let out_dir = std::path::Path::new("completions");
        let pkg_name = std::env::var("CARGO_PKG_NAME").expect("have CARGO_PKG_NAME");
        let mut cmd = <cli::Cli as clap::CommandFactory>::command();
        for &shell in Shell::value_variants() {
            let out_dir = out_dir.join(shell.to_string());
            std::fs::create_dir_all(&out_dir).expect("create_dir_all");
            if let Err(err) = generate_to(shell, &mut cmd, &pkg_name, &out_dir) {
                panic!("failed to generate completion for {shell}: {err}");
            }
        }
    }
}
