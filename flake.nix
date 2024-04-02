rec {
  description = "OneDrive as a block device";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    inherit (nixpkgs) lib;
    eachSystem =
      lib.genAttrs (
        lib.filter
          (lib.hasSuffix "-linux")
          lib.systems.flakeExposed);
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

        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [ pkg-config installShellFiles ];
        buildInputs = [ openssl ];

        buildFeatures = [ "completion" ];

        env.CFG_RELEASE = version;

        postInstall = ''
          mkdir -p $out/etc/systemd/system
          substitute ./contrib/orb@.example.service $out/etc/systemd/system/orb@.service \
            --replace-fail '/usr/bin/orb' "$out/bin/orb"

          installShellCompletion \
            --bash completions/bash/${pname}.bash \
            --fish completions/fish/${pname}.fish \
            --zsh completions/zsh/_${pname}
        '';

        meta = {
          inherit description;
          homepage = "https://github.com/oxalica/orb";
          mainProgram = "orb";
          license = [ lib.licenses.gpl3Plus ];
          platforms = lib.platforms.linux;
        };
      };

      ublk-chown-unprivileged = with pkgs; rustPlatform.buildRustPackage {
        pname = "ublk-chown-unprivileged";
        version = "git-${rev}";
        src = self;

        cargoLock.lockFile = ./Cargo.lock;

        buildAndTestSubdir = "orb-ublk";
        cargoBuildFlags = [ "--example=ublk-chown-unprivileged" ];

        # Tests require ublk_drv.
        doCheck = false;

        postInstall = ''
          install -Dm755 -t $out/libexec target/*/release/examples/ublk-chown-unprivileged
          mkdir -p $out/etc/udev/rules.d
          substitute ./contrib/19-ublk-unprivileged.example.rules $out/etc/udev/rules.d/19-ublk-unprivileged.rules \
            --replace-fail '/usr/libexec/' "$out/libexec/"
        '';

        meta = {
          description = "udev rules to enable unprivileged ublk usage";
          homepage = "https://github.com/oxalica/orb";
          license = with lib.licenses; [ mit asl20 ];
          platforms = lib.platforms.linux;
        };
      };

      btrfs-progs-fix-zoned-bgt = with pkgs; btrfs-progs.overrideAttrs (old: {
        version = old.version + "-fix-zoned-bgt";
        patches = old.patches or [ ] ++ [
          ./contrib/btrfs-progs-pr-767-zoned-bgt.patch
        ];
      });
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

    nixosModules = rec {
      default = orb;
      orb = import ./contrib/orb.nix {
        inherit self;
      };
    };
  };
}
