{ self }:
{ lib, config, pkgs, ... }:
let
  inherit (lib)
    literalExpression
    literalMD
    mdDoc
    mkIf
    mkOption
    types
  ;

  cfg = config.services.orb;

  sizeType = types.either types.ints.unsigned types.str;

  lowIdThreshould = 50;

  toml = pkgs.formats.toml {};
  mkConfigFile = name: config: (toml.generate name config).overrideAttrs (old: {
    buildCommand = old.buildCommand + ''
      ${lib.getExe cfg.package} verify -c $out
    '';
  });

  settingsType = types.submodule {
    freeformType = toml.type;

    options = {
      ublk = {
        id = mkOption {
          type = types.ints.unsigned;
          example = "80";
          description = mdDoc ''
            The device id, ie. the integer part in `/dev/ublk{b,c}X`, to use.

            Low ids (<${toString lowIdThreshould}) are not recommended and will generate
            warnings, to avoid colliding with auto-generated ids.
          '';
        };
        unprivileged = mkOption {
          type = types.enum [ false ];
          default = false;
          description = mdDoc ''
            Whether to create an unprivileged block device. This must be
            `false` since this module generates privileged systemd services.
          '';
        };
      };
      device = {
        dev_size = mkOption {
          type = sizeType;
          description = mdDoc ''
            Total device size, must be a multiple of `zone_size`.
          '';
        };
        zone_size = mkOption {
          type = sizeType;
          description = mdDoc ''
            The size of a zone, the minimal reset (delete) unit. It cannot be changed
            without losing all the data. Some filesystems have requirement on it, eg.
            BTRFS requires it to be `4MiB..=4GiB`.
          '';
        };
        min_chunk_size = mkOption {
          type = sizeType;
          description = mdDoc ''
            The minimal size for a standalone chunk to minimize fragmentation, must be
            less than `max_chunk_size`. Chunks smaller than it will be fully rewritten on
            committing until they grow larger than this limit.
          '';
        };
        max_chunk_size = mkOption {
          type = sizeType;
          description = mdDoc ''
            The maximum size a chunk can be, also the maximum buffer size for each zone,
            must be less than `zone_size`. When a trailing chunk in a zone is grown
            exceeding this size, following write requests will wait the chunk to be
            committed to backend before continue.
          '';
        };
      };
      # `onedrive.state_dir` must be `null` but toml generators will fail
      # instead of skipping.
    };
  };

in {
  options.services.orb = {
    enable = mkOption {
      type = lib.types.bool;
      description = "Whether to enable orb network block device service.";
      default = cfg.instances != {};
      defaultText = literalExpression "config.services.orb.instances != {}";
      example = true;
    };

    package = mkOption {
      description = mdDoc "The orb package to install and for systemd services";
      type = types.package;
      default = self.packages.${pkgs.system}.orb;
      defaultText = literalMD "orb package from its flake output";
    };

    instances = mkOption {
      description = mdDoc "Set of orb instances.";
      default = {};
      type = with types;
        attrsOf (
          submodule {
            options = {
              settings = mkOption {
                description = "orb configurations.";
                type = settingsType;
                example = {
                  ublk.id = 50;
                  device = {
                    dev_size = "1TiB";
                    zone_size = "256MiB";
                    min_chunk_size = "1MiB";
                    max_chunk_size = "256MiB";
                    max_concurrent_streams = 16;
                    max_concurrent_commits = 4;
                  };
                  backend.onedrive.remote_dir = "/orb";
                };
              };
            };
          }
        );
    };
  };

  config = mkIf cfg.enable {
    assertions = let
      groups = lib.groupBy
        (name: toString (cfg.instances.${name}.settings.ublk.id or null))
        (lib.attrNames cfg.instances);
    in lib.mapAttrsToList (id: names: {
      assertion = lib.length names == 1;
      message = "orb instances ublk.id collision on ${id}: ${lib.concatStringsSep ", " names}";
    }) groups;

    warnings =
      lib.filter (msg: msg != null)
        (lib.mapAttrsToList (name: instance:
          let id = instance.settings.ublk.id; in
          if id < lowIdThreshould then
            "orb instance '${name}' uses a low id ${toString id} < ${toString lowIdThreshould} risking collision"
          else
            null
        ) cfg.instances);

    systemd.packages = [ cfg.package ];
    environment.systemPackages = [ cfg.package ];

    # Do not accidentally stop active filesystems.
    systemd.services."orb@" = {
      overrideStrategy = "asDropin";
      restartIfChanged = false;
      stopIfChanged = false;
    };

    environment.etc = lib.mapAttrs' (name: instance: {
      name = "orb/${name}.toml";
      value.source = mkConfigFile "${name}.toml" instance.settings;
    }) cfg.instances;
  };
}
