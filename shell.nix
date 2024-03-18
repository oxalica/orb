with import <nixpkgs> { };
mkShell {
  nativeBuildInputs = [ pkg-config rustPlatform.bindgenHook moreutils ];
  buildInputs = [ linuxHeaders openssl ];
  env = {
    RUST_BACKTRACE = "1";
    RUST_LOG = "debug,orb=trace";
  };
}
