rec {
  description = "OneDrive Block Device Daemon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    inherit (nixpkgs) lib;
    eachSystem = lib.genAttrs lib.systems.flakeExposed;
  in {
    packages = eachSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      rev = self.rev or (lib.warn "Git changes are not committed" (self.dirtyRev or "dirty"));
    in rec {
      default = orb;
      orb = with pkgs; rustPlatform.buildRustPackage rec {
        pname = "orb";
        version = "git-${rev}";
        src = self;

        cargoLock = {
          lockFile = ./Cargo.lock;
          # WAIT: onedrive-api release.
          allowBuiltinFetchGit = true;
        };

        nativeBuildInputs = [ pkg-config rustPlatform.bindgenHook installShellFiles ];
        buildInputs = [ linuxHeaders openssl ];

        buildFeatures = [ "completion" ];

        postInstall = ''
          install -DT ./orb@.example.service $out/etc/systemd/system/orb@.service
          installShellCompletion \
            --bash completions/bash/${pname}.bash \
            --fish completions/fish/${pname}.fish \
            --zsh completions/zsh/_${pname}
        '';

        meta = {
          inherit description;
          homepage = "https://github.com/oxalica/orb";
          mainProgram = "orb";
        };
      };
    });

    devShells = eachSystem (system: {
      without-rust =
        with nixpkgs.legacyPackages.${system};
        mkShell {
          nativeBuildInputs = [ pkg-config rustPlatform.bindgenHook ];
          buildInputs = [ linuxHeaders openssl ];
          env = {
            RUST_BACKTRACE = "1";
            RUST_LOG = "debug,orb=trace";
          };
        };
    });
  };
}